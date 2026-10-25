-- RLS Check: read-only snapshot of your Supabase security settings.
-- Paste into Supabase > SQL Editor and run. It only READS the system catalog
-- (no data from your tables, no changes). Copy the single JSON value it returns.

with
exposed as (
  select unnest(array['public']) as schema_name
),
tbls as (
  select n.nspname as schema, c.relname as name, c.relkind as kind,
         c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced,
         coalesce((select array_agg(a.attname::text order by a.attnum)
                   from pg_attribute a
                   where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped), '{}') as columns,
         coalesce(c.reloptions, '{}') as options
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname in (select schema_name from exposed)
    and c.relkind in ('r', 'p', 'v', 'm')
),
pols as (
  select schemaname as schema, tablename as table, policyname as name, permissive,
         roles::text[] as roles, cmd, qual, with_check
  from pg_policies
  where schemaname in (select schema_name from exposed)
),
grnts as (
  select table_schema as schema, table_name as table, grantee, privilege_type as privilege
  from information_schema.role_table_grants
  where table_schema in (select schema_name from exposed)
    and grantee in ('anon', 'authenticated')
),
funcs as (
  select n.nspname as schema, p.proname as name,
         pg_get_function_identity_arguments(p.oid) as args,
         pg_get_function_result(p.oid) as returns,
         p.provolatile as volatility,
         p.prosecdef as security_definer,
         coalesce(p.proconfig, '{}') as config,
         has_function_privilege('anon', p.oid, 'execute') as anon_can_execute,
         has_function_privilege('authenticated', p.oid, 'execute') as authenticated_can_execute
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname in (select schema_name from exposed)
    and p.prokind = 'f'
),
buckets as (
  select coalesce(
    (select jsonb_agg(jsonb_build_object('id', b.id, 'public', b.public))
     from storage.buckets b),
    '[]'::jsonb) as list
  where to_regclass('storage.buckets') is not null
)
select jsonb_build_object(
  'tool', 'rls-check',
  'version', 1,
  'tables', coalesce((select jsonb_agg(to_jsonb(t)) from tbls t), '[]'::jsonb),
  'policies', coalesce((select jsonb_agg(to_jsonb(p)) from pols p), '[]'::jsonb),
  'grants', coalesce((select jsonb_agg(to_jsonb(g)) from grnts g), '[]'::jsonb),
  'functions', coalesce((select jsonb_agg(to_jsonb(f)) from funcs f), '[]'::jsonb),
  'buckets', coalesce((select list from buckets), '[]'::jsonb)
) as rls_check_snapshot;
