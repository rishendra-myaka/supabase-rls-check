// RLS Check analyser: turns a catalog snapshot (from snapshot.sql) into plain-English findings.
// Pure functions, no I/O, so the web page, the CLI and the tests all use the same code.

export type Snapshot = {
  tool?: string;
  version?: number;
  tables: {
    schema: string;
    name: string;
    kind: 'r' | 'p' | 'v' | 'm';
    rls_enabled: boolean;
    rls_forced: boolean;
    columns: string[];
    options: string[];
  }[];
  policies: {
    schema: string;
    table: string;
    name: string;
    permissive: 'PERMISSIVE' | 'RESTRICTIVE';
    roles: string[];
    cmd: 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'ALL';
    qual: string | null;
    with_check: string | null;
  }[];
  grants: { schema: string; table: string; grantee: 'anon' | 'authenticated'; privilege: string }[];
  functions: {
    schema: string;
    name: string;
    args: string;
    returns?: string;
    volatility?: 'i' | 's' | 'v';
    security_definer: boolean;
    config: string[];
    anon_can_execute: boolean;
    authenticated_can_execute: boolean;
  }[];
  buckets: { id: string; public: boolean }[];
};

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Finding = {
  id: string;
  severity: Severity;
  title: string;
  target: string;
  why: string;
  fix: string;
  sql?: string;
};

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SENSITIVE = /(^|_)(email|phone|mobile|address|dob|birth|ssn|passport|password|token|secret|salary|iban|card|ip_address|location|lat|lng|full_name|first_name|last_name)($|_)/i;
const ALWAYS_TRUE = /^\s*\(?\s*true\s*\)?\s*$/i;

const q = (s: string) => `"${s.replace(/"/g, '""')}"`;
const fq = (schema: string, name: string) => `${q(schema)}.${q(name)}`;

function isAlwaysTrue(expr: string | null) {
  return expr == null || ALWAYS_TRUE.test(expr);
}

function rolesOpen(roles: string[]) {
  return roles.includes('public') || roles.includes('anon');
}

export function parseSnapshot(text: string): Snapshot {
  let value: unknown;
  try {
    value = JSON.parse(text.trim());
  } catch {
    throw new Error('That is not valid JSON. Copy the whole value from the rls_check_snapshot column.');
  }
  // Accept the raw object, or a row like { "rls_check_snapshot": {...} } / [ {...} ] from an export.
  if (Array.isArray(value)) value = value[0];
  if (value && typeof value === 'object' && 'rls_check_snapshot' in value) {
    value = (value as { rls_check_snapshot: unknown }).rls_check_snapshot;
  }
  const s = value as Partial<Snapshot>;
  if (!s || !Array.isArray(s.tables) || !Array.isArray(s.policies)) {
    throw new Error('This does not look like an RLS Check snapshot. Run snapshot.sql and paste its result.');
  }
  return {
    tables: s.tables,
    policies: s.policies,
    grants: s.grants ?? [],
    functions: s.functions ?? [],
    buckets: s.buckets ?? [],
  };
}

export function analyze(snap: Snapshot): Finding[] {
  const findings: Finding[] = [];
  const grantsFor = (schema: string, table: string) =>
    snap.grants.filter((g) => g.schema === schema && g.table === table);

  for (const t of snap.tables) {
    const target = `${t.schema}.${t.name}`;
    const grants = grantsFor(t.schema, t.name);
    const anonPrivs = new Set(grants.filter((g) => g.grantee === 'anon').map((g) => g.privilege));
    const authPrivs = new Set(grants.filter((g) => g.grantee === 'authenticated').map((g) => g.privilege));
    const reachable = anonPrivs.size > 0 || authPrivs.size > 0;
    const sensitiveCols = t.columns.filter((c) => SENSITIVE.test(c));
    const policies = snap.policies.filter((p) => p.schema === t.schema && p.table === t.name);

    // Views: run with the owner's rights unless security_invoker is set, so they skip RLS.
    if (t.kind === 'v' || t.kind === 'm') {
      const invoker = t.options.some((o) => /^security_invoker=(true|on|1)$/i.test(o));
      if (reachable && !invoker) {
        findings.push({
          id: 'view-bypasses-rls',
          severity: anonPrivs.has('SELECT') ? 'high' : 'medium',
          title: 'View can bypass row-level security',
          target,
          why: 'Views run with the permissions of their owner by default, so the API can read rows that the underlying tables\' policies would hide.',
          fix: t.kind === 'v'
            ? 'Make the view respect the caller\'s RLS (Postgres 15+), or revoke API access to it.'
            : 'Materialized views never apply RLS. Revoke API access, or expose the data through a function that checks auth.uid().',
          sql: t.kind === 'v'
            ? `alter view ${fq(t.schema, t.name)} set (security_invoker = on);`
            : `revoke all on ${fq(t.schema, t.name)} from anon, authenticated;`,
        });
      }
      continue;
    }

    if (!t.rls_enabled) {
      if (reachable) {
        findings.push({
          id: 'rls-disabled',
          severity: anonPrivs.size > 0 ? 'critical' : 'high',
          title: 'Row-level security is OFF on a table the API can reach',
          target,
          why: `${anonPrivs.size > 0 ? 'Anyone with your public (anon) key' : 'Any signed-in user'} can ${[...new Set([...anonPrivs, ...authPrivs])].map((p) => p.toLowerCase()).join(', ')} every row${sensitiveCols.length ? `, including ${sensitiveCols.slice(0, 4).join(', ')}` : ''}.`,
          fix: 'Turn RLS on, then add a policy for each thing users should be allowed to do. With RLS on and no policy, the table is closed by default.',
          sql: `alter table ${fq(t.schema, t.name)} enable row level security;`,
        });
      } else {
        findings.push({
          id: 'rls-disabled-unreachable',
          severity: 'low',
          title: 'RLS is off, but the API roles have no access',
          target,
          why: 'Safe today because anon and authenticated have no table privileges. A future GRANT would expose every row at once.',
          fix: 'Enable RLS anyway so the table stays closed if someone grants access later.',
          sql: `alter table ${fq(t.schema, t.name)} enable row level security;`,
        });
      }
      continue;
    }

    if (policies.length === 0 && reachable) {
      findings.push({
        id: 'rls-no-policies',
        severity: 'info',
        title: 'RLS is on but there are no policies',
        target,
        why: 'Nobody can read or write this table through the API. That is safe; just make sure it is what you intended.',
        fix: 'If the app needs this table, add policies for the specific operations it uses.',
      });
    }

    for (const p of policies) {
      const pt = `${target} → policy "${p.name}" (${p.cmd})`;
      const exprs = `${p.qual ?? ''} ${p.with_check ?? ''}`;

      if (/user_metadata|raw_user_meta_data/i.test(exprs)) {
        findings.push({
          id: 'policy-uses-user-metadata',
          severity: 'critical',
          title: 'Policy trusts user_metadata, which users can edit themselves',
          target: pt,
          why: 'Any signed-in user can change their own user_metadata with supabase.auth.updateUser(), so a policy based on it (for example a role) can be bypassed.',
          fix: 'Store roles in a table users cannot write, or in app_metadata (set only from the server), and check that instead.',
        });
      }

      const writes = p.cmd !== 'SELECT';
      const usingOpen = isAlwaysTrue(p.qual) && (p.cmd === 'SELECT' || p.cmd === 'UPDATE' || p.cmd === 'DELETE' || p.cmd === 'ALL');
      const checkOpen = (p.cmd === 'INSERT' || p.cmd === 'UPDATE' || p.cmd === 'ALL') && isAlwaysTrue(p.with_check ?? p.qual);
      const open = rolesOpen(p.roles);
      const who = open ? 'anyone (even without signing in)' : 'any signed-in user';

      if (p.permissive === 'PERMISSIVE' && writes && (usingOpen || checkOpen)) {
        findings.push({
          id: 'policy-open-write',
          severity: open ? 'critical' : 'high',
          title: `Policy lets ${who} ${p.cmd === 'ALL' ? 'change' : p.cmd.toLowerCase()} any row`,
          target: pt,
          why: `The condition is always true, so ${who} can ${p.cmd === 'ALL' ? 'insert, update or delete' : p.cmd.toLowerCase()} rows that belong to other people.`,
          fix: 'Limit the policy to the row owner, for example using ((select auth.uid()) = user_id), and add WITH CHECK for inserts and updates.',
        });
      } else if (p.permissive === 'PERMISSIVE' && p.cmd === 'SELECT' && usingOpen && sensitiveCols.length > 0) {
        findings.push({
          id: 'policy-open-read-sensitive',
          severity: open ? 'medium' : 'low',
          title: `Review: ${who} can read every row, and some columns look personal`,
          target: pt,
          why: `Columns like ${sensitiveCols.slice(0, 4).join(', ')} are readable by ${who}. That is right for public data (a shop's address in a directory) and wrong for personal data (a customer's address).`,
          fix: 'Restrict the policy to the owner, or move public fields into a separate table or a view with security_invoker.',
        });
      }

      // Postgres stores the wrapped form as "( SELECT auth.uid() AS uid)"; flag only calls that are not wrapped.
      const unwrapped = exprs.replace(/\(\s*select\s+auth\.(uid|jwt|role)\(\)(\s+as\s+\w+)?\s*\)/gi, '');
      const perRow = unwrapped.match(/auth\.(uid|jwt|role)\(\)/i);
      if (perRow) {
        const call = perRow[0].toLowerCase();
        findings.push({
          id: 'policy-auth-call-per-row',
          severity: 'low',
          title: `${call} is evaluated once per row (slow on big tables)`,
          target: pt,
          why: `Postgres calls ${call} for every row it checks. Wrapping it in a sub-select lets Postgres compute it once per query, which can make large queries many times faster.`,
          fix: `Write (select ${call}) instead of ${call} in the policy.`,
        });
      }
    }

    if (anonPrivs.has('TRUNCATE') || authPrivs.has('TRUNCATE')) {
      findings.push({
        id: 'grant-truncate',
        severity: 'low',
        title: 'API roles hold TRUNCATE (not checked by RLS)',
        target,
        why: 'The Data API cannot send TRUNCATE, so this is not exploitable through supabase-js. But TRUNCATE ignores row-level security, so if these roles are ever used another way (a SQL function, a direct connection) the whole table could be emptied. Supabase\'s default privileges often add it.',
        fix: 'Revoke the privileges the API never needs: TRUNCATE, REFERENCES and TRIGGER.',
        sql: `revoke truncate, references, trigger on ${fq(t.schema, t.name)} from anon, authenticated;`,
      });
    }
  }

  for (const f of snap.functions) {
    if (!f.security_definer) continue;
    // Trigger and event-trigger functions cannot be called through the API.
    if (f.returns && /^(event_)?trigger$/i.test(f.returns.trim())) continue;
    const target = `${f.schema}.${f.name}(${f.args})`;
    const pinned = f.config.some((c) => /^search_path=/i.test(c));
    if (!pinned) {
      findings.push({
        id: 'definer-search-path',
        severity: f.anon_can_execute || f.authenticated_can_execute ? 'high' : 'medium',
        title: 'SECURITY DEFINER function without a fixed search_path',
        target,
        why: 'The function runs with its owner\'s rights. Without a fixed search_path, a caller who can create objects may make it run their code instead of yours.',
        fix: 'Pin the search_path to empty and use schema-qualified names inside the function.',
        sql: `alter function ${fq(f.schema, f.name)}(${f.args}) set search_path = '';`,
      });
    }
    if (f.anon_can_execute) {
      const readOnly = f.volatility === 's' || f.volatility === 'i';
      findings.push({
        id: 'definer-callable-by-anon',
        severity: readOnly ? 'info' : 'medium',
        title: 'Anyone can call a SECURITY DEFINER function',
        target,
        why: readOnly
          ? 'It is read-only (STABLE/IMMUTABLE) but bypasses RLS and can be called with just your public key. Check it only returns data you mean to be public.'
          : 'It bypasses RLS, can change data, and can be called with just your public key. Fine only if it checks who is calling.',
        fix: 'If it is not meant to be public, revoke execute from anon (and from public, which anon inherits).',
        sql: `revoke execute on function ${fq(f.schema, f.name)}(${f.args}) from public, anon;`,
      });
    }
  }

  for (const b of snap.buckets) {
    if (b.public) {
      findings.push({
        id: 'public-bucket',
        severity: 'info',
        title: 'Public storage bucket',
        target: `storage bucket "${b.id}"`,
        why: 'Anyone with a file\'s URL can download it, without signing in. Right for logos and avatars; wrong for documents, IDs or invoices.',
        fix: 'If files are private, make the bucket private and serve them with signed URLs.',
      });
    }
  }

  return findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

export function summarize(findings: Finding[]) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function toMarkdown(findings: Finding[]): string {
  const c = summarize(findings);
  const lines = [
    '# RLS Check report',
    '',
    `Critical ${c.critical} · High ${c.high} · Medium ${c.medium} · Low ${c.low} · Info ${c.info}`,
    '',
  ];
  if (findings.length === 0) lines.push('No problems found.');
  for (const f of findings) {
    lines.push(`## [${f.severity.toUpperCase()}] ${f.title}`, '', `**Where:** ${f.target}`, '', `**Why it matters:** ${f.why}`, '', `**Fix:** ${f.fix}`);
    if (f.sql) lines.push('', '```sql', f.sql, '```');
    lines.push('');
  }
  return lines.join('\n');
}
