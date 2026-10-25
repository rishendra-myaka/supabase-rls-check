/// <reference types="node" />
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { analyze, parseSnapshot, summarize, toMarkdown, type Snapshot } from '../src/analyze.ts';

const base = (): Snapshot => ({ tables: [], policies: [], grants: [], functions: [], buckets: [] });
const table = (name: string, over: Partial<Snapshot['tables'][number]> = {}): Snapshot['tables'][number] => ({
  schema: 'public', name, kind: 'r', rls_enabled: true, rls_forced: false, columns: ['id'], options: [], ...over,
});
const grant = (t: string, grantee: 'anon' | 'authenticated', privilege: string) => ({ schema: 'public', table: t, grantee, privilege });
const ids = (s: Snapshot) => analyze(s).map((f) => f.id);

test('RLS off on a table anon can read is critical, and mentions personal columns', () => {
  const s = base();
  s.tables.push(table('profiles', { rls_enabled: false, columns: ['id', 'email', 'phone'] }));
  s.grants.push(grant('profiles', 'anon', 'SELECT'));
  const [f] = analyze(s);
  assert.equal(f.id, 'rls-disabled');
  assert.equal(f.severity, 'critical');
  assert.match(f.why, /email/);
  assert.match(f.sql!, /enable row level security/);
});

test('RLS off but no API grants is only low', () => {
  const s = base();
  s.tables.push(table('internal_log', { rls_enabled: false }));
  assert.deepEqual(analyze(s).map((f) => [f.id, f.severity]), [['rls-disabled-unreachable', 'low']]);
});

test('open write policy for anon is critical; for authenticated is high', () => {
  const s = base();
  s.tables.push(table('posts'));
  s.grants.push(grant('posts', 'anon', 'UPDATE'));
  s.policies.push({ schema: 'public', table: 'posts', name: 'anyone edits', permissive: 'PERMISSIVE', roles: ['anon'], cmd: 'UPDATE', qual: 'true', with_check: 'true' });
  s.policies.push({ schema: 'public', table: 'posts', name: 'members insert', permissive: 'PERMISSIVE', roles: ['authenticated'], cmd: 'INSERT', qual: null, with_check: 'true' });
  const f = analyze(s).filter((x) => x.id === 'policy-open-write');
  assert.deepEqual(f.map((x) => x.severity), ['critical', 'high']);
});

test('public read of a table with personal columns is flagged; public read of a catalogue is not', () => {
  const s = base();
  s.tables.push(table('customers', { columns: ['id', 'email'] }), table('products', { columns: ['id', 'title', 'price'] }));
  s.grants.push(grant('customers', 'anon', 'SELECT'), grant('products', 'anon', 'SELECT'));
  for (const t of ['customers', 'products']) {
    s.policies.push({ schema: 'public', table: t, name: 'public read', permissive: 'PERMISSIVE', roles: ['anon', 'authenticated'], cmd: 'SELECT', qual: 'true', with_check: null });
  }
  const f = analyze(s);
  assert.equal(f.filter((x) => x.id === 'policy-open-read-sensitive').length, 1);
  assert.match(f[0].target, /customers/);
});

test('policies trusting user_metadata are critical', () => {
  const s = base();
  s.tables.push(table('admin_notes'));
  s.policies.push({
    schema: 'public', table: 'admin_notes', name: 'admins', permissive: 'PERMISSIVE', roles: ['authenticated'], cmd: 'SELECT',
    qual: "((auth.jwt() -> 'user_metadata'::text) ->> 'role'::text) = 'admin'::text", with_check: null,
  });
  assert.ok(analyze(s).some((f) => f.id === 'policy-uses-user-metadata' && f.severity === 'critical'));
});

test('auth.uid() without a sub-select is a performance hint; the wrapped form is not', () => {
  const s = base();
  s.tables.push(table('notes'));
  s.policies.push(
    { schema: 'public', table: 'notes', name: 'slow', permissive: 'PERMISSIVE', roles: ['authenticated'], cmd: 'SELECT', qual: '(auth.uid() = user_id)', with_check: null },
    { schema: 'public', table: 'notes', name: 'fast', permissive: 'PERMISSIVE', roles: ['authenticated'], cmd: 'DELETE', qual: '(( SELECT auth.uid() AS uid) = user_id)', with_check: null },
  );
  const perf = analyze(s).filter((f) => f.id === 'policy-auth-call-per-row');
  assert.equal(perf.length, 1);
  assert.match(perf[0].target, /slow/);
});

test('views without security_invoker that the API can read are flagged', () => {
  const s = base();
  s.tables.push(table('order_summary', { kind: 'v' }), table('safe_view', { kind: 'v', options: ['security_invoker=true'] }));
  s.grants.push(grant('order_summary', 'anon', 'SELECT'), grant('safe_view', 'anon', 'SELECT'));
  const f = analyze(s);
  assert.deepEqual(f.map((x) => [x.id, x.target]), [['view-bypasses-rls', 'public.order_summary']]);
});

test('SECURITY DEFINER functions: unpinned search_path and anon execute', () => {
  const s = base();
  s.functions.push(
    { schema: 'public', name: 'risky', args: 'p uuid', security_definer: true, config: [], anon_can_execute: true, authenticated_can_execute: true },
    { schema: 'public', name: 'pinned', args: '', security_definer: true, config: ['search_path=""'], anon_can_execute: false, authenticated_can_execute: true },
    { schema: 'public', name: 'plain', args: '', security_definer: false, config: [], anon_can_execute: true, authenticated_can_execute: true },
  );
  assert.deepEqual(ids(s).sort(), ['definer-callable-by-anon', 'definer-search-path']);
});

test('TRUNCATE grant, public bucket, and RLS-on-without-policies', () => {
  const s = base();
  s.tables.push(table('jobs'));
  s.grants.push(grant('jobs', 'authenticated', 'TRUNCATE'));
  s.buckets.push({ id: 'avatars', public: true }, { id: 'invoices', public: false });
  const got = ids(s);
  assert.ok(got.includes('grant-truncate'));
  assert.ok(got.includes('rls-no-policies'));
  assert.equal(got.filter((x) => x === 'public-bucket').length, 1);
});

test('a well-configured project produces no warnings', () => {
  const s = base();
  s.tables.push(table('bookings', { columns: ['id', 'customer_id', 'starts_at'] }));
  s.grants.push(grant('bookings', 'authenticated', 'SELECT'));
  s.policies.push({ schema: 'public', table: 'bookings', name: 'own', permissive: 'PERMISSIVE', roles: ['authenticated'], cmd: 'SELECT', qual: '(customer_id = ( SELECT auth.uid() AS uid))', with_check: null });
  s.functions.push({ schema: 'public', name: 'book_slot', args: 'uuid, timestamptz', security_definer: true, config: ['search_path=""'], anon_can_execute: false, authenticated_can_execute: true });
  assert.deepEqual(analyze(s), []);
});

test('findings are sorted from most to least severe, and the summary counts them', () => {
  const s = base();
  s.tables.push(table('a', { rls_enabled: false }), table('b', { rls_enabled: false }));
  s.grants.push(grant('b', 'anon', 'SELECT'));
  const f = analyze(s);
  assert.deepEqual(f.map((x) => x.severity), ['critical', 'low']);
  assert.equal(summarize(f).critical, 1);
  assert.match(toMarkdown(f), /\[CRITICAL\]/);
});

test('parseSnapshot accepts the raw value, an exported row, or a JSON array, and explains bad input', () => {
  const raw = JSON.stringify(base());
  assert.ok(parseSnapshot(raw).tables);
  assert.ok(parseSnapshot(JSON.stringify({ rls_check_snapshot: base() })).tables);
  assert.ok(parseSnapshot(JSON.stringify([{ rls_check_snapshot: base() }])).tables);
  assert.throws(() => parseSnapshot('not json'), /not valid JSON/);
  assert.throws(() => parseSnapshot('{"hello":1}'), /does not look like/);
});

test('trigger functions are skipped; read-only public functions are info only', () => {
  const s = base();
  s.functions.push(
    { schema: 'public', name: 'rls_auto_enable', args: '', returns: 'event_trigger', volatility: 'v', security_definer: true, config: [], anon_can_execute: true, authenticated_can_execute: true },
    { schema: 'public', name: 'on_signup', args: '', returns: 'trigger', volatility: 'v', security_definer: true, config: [], anon_can_execute: true, authenticated_can_execute: true },
    { schema: 'public', name: 'public_stats', args: '', returns: 'integer', volatility: 's', security_definer: true, config: ['search_path=""'], anon_can_execute: true, authenticated_can_execute: true },
  );
  assert.deepEqual(analyze(s).map((f) => [f.id, f.severity, f.target]), [['definer-callable-by-anon', 'info', 'public.public_stats()']]);
});

test('real project (Book a Slot, captured from Supabase): only deliberate, reviewable items remain', async () => {
  const { readFileSync } = await import('node:fs');
  const snap = parseSnapshot(readFileSync(new URL('./fixtures/book-a-slot.json', import.meta.url), 'utf8'));
  const f = analyze(snap);
  // The public business directory exposes business addresses on purpose: a review item, not an alarm.
  assert.deepEqual(f.map((x) => [x.id, x.severity]), [
    ['policy-open-read-sensitive', 'medium'],
    ['definer-callable-by-anon', 'info'],
  ]);
  assert.match(f[0].target, /businesses/);
  assert.match(f[1].target, /get_taken_slots/);
});
