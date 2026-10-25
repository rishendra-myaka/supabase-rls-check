import './style.css';

import { analyze, parseSnapshot, summarize, toMarkdown, type Finding, type Snapshot } from './analyze.ts';
import sql from './snapshot.sql?raw';

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;

const sqlBox = $<HTMLPreElement>('sql');
const input = $<HTMLTextAreaElement>('input');
const error = $<HTMLParagraphElement>('error');
const report = $<HTMLElement>('report');
let lastFindings: Finding[] = [];

sqlBox.textContent = sql;

$('copy').addEventListener('click', async (e) => {
  const button = e.currentTarget as HTMLButtonElement;
  try {
    await navigator.clipboard.writeText(sql);
    button.textContent = 'Copied';
  } catch {
    // Clipboard blocked: select the text so the user can press Ctrl+C.
    const range = document.createRange();
    range.selectNodeContents(sqlBox);
    getSelection()?.removeAllRanges();
    getSelection()?.addRange(range);
    button.textContent = 'Press Ctrl+C';
  }
  setTimeout(() => (button.textContent = 'Copy query'), 2000);
});

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string, text?: string) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function render(findings: Finding[]) {
  lastFindings = findings;
  const counts = summarize(findings);
  const summary = $('summary');
  summary.replaceChildren(
    ...(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => {
      const chip = el('span', `chip ${s}`, `${counts[s]} ${s}`);
      return chip;
    }),
  );

  const list = $('findings');
  if (findings.length === 0) {
    list.replaceChildren(el('p', 'ok', 'No problems found. Nice work.'));
  } else {
    list.replaceChildren(
      ...findings.map((f) => {
        const card = el('article', `finding ${f.severity}`);
        const head = el('div', 'finding-head');
        head.append(el('span', `badge ${f.severity}`, f.severity), el('h3', undefined, f.title));
        card.append(head, el('p', 'target', f.target));
        const why = el('p');
        why.append(el('strong', undefined, 'Why it matters: '), document.createTextNode(f.why));
        const fix = el('p');
        fix.append(el('strong', undefined, 'Fix: '), document.createTextNode(f.fix));
        card.append(why, fix);
        if (f.sql) card.append(el('pre', 'fix-sql', f.sql));
        return card;
      }),
    );
  }
  report.hidden = false;
  report.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function run(text: string) {
  error.hidden = true;
  try {
    render(analyze(parseSnapshot(text)));
  } catch (e) {
    error.textContent = (e as Error).message;
    error.hidden = false;
    report.hidden = true;
  }
}

$('run').addEventListener('click', () => run(input.value));

// A deliberately broken project, so visitors can see what the report looks like.
const EXAMPLE: Snapshot = {
  tables: [
    { schema: 'public', name: 'profiles', kind: 'r', rls_enabled: false, rls_forced: false, columns: ['id', 'full_name', 'email', 'phone'], options: [] },
    { schema: 'public', name: 'orders', kind: 'r', rls_enabled: true, rls_forced: false, columns: ['id', 'user_id', 'total'], options: [] },
    { schema: 'public', name: 'order_summary', kind: 'v', rls_enabled: false, rls_forced: false, columns: ['user_id', 'total'], options: [] },
  ],
  policies: [
    { schema: 'public', table: 'orders', name: 'users update orders', permissive: 'PERMISSIVE', roles: ['authenticated'], cmd: 'UPDATE', qual: 'true', with_check: 'true' },
    { schema: 'public', table: 'orders', name: 'admins read all', permissive: 'PERMISSIVE', roles: ['authenticated'], cmd: 'SELECT', qual: "((auth.jwt() -> 'user_metadata'::text) ->> 'role'::text) = 'admin'::text", with_check: null },
  ],
  grants: [
    { schema: 'public', table: 'profiles', grantee: 'anon', privilege: 'SELECT' },
    { schema: 'public', table: 'orders', grantee: 'authenticated', privilege: 'UPDATE' },
    { schema: 'public', table: 'order_summary', grantee: 'anon', privilege: 'SELECT' },
  ],
  functions: [
    { schema: 'public', name: 'apply_discount', args: 'order_id uuid', returns: 'void', volatility: 'v', security_definer: true, config: [], anon_can_execute: true, authenticated_can_execute: true },
  ],
  buckets: [{ id: 'invoices', public: true }],
};

$('example').addEventListener('click', () => {
  input.value = JSON.stringify(EXAMPLE, null, 2);
  run(input.value);
});

$('download').addEventListener('click', () => {
  const blob = new Blob([toMarkdown(lastFindings)], { type: 'text/markdown' });
  const a = el('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'rls-check-report.md';
  a.click();
  URL.revokeObjectURL(a.href);
});
