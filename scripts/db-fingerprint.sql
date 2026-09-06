-- A content fingerprint of a schautrack database, for proving a migration was
-- lossless.
--
-- Row counts alone are not proof: they survive a restore that coerced NULL to
-- '', truncated numeric precision, or dropped a column's contents. So every
-- table is reduced to an md5 over its fully-rendered rows.
--
-- THE TABLE LIST COMES FROM THE CATALOG, NOT FROM THIS FILE. An earlier version
-- hand-listed seven tables and the surrounding script then claimed "every table
-- digest is identical". The schema has twenty-four: a restore that lost every
-- passkey, API token, TOTP backup code, invite code, weight goal and admin
-- setting would have produced a clean diff and a congratulatory message. A
-- curated list also ages out silently — each new migration adds a table nobody
-- remembers to add here.
--
-- Rows are ordered by their own text representation rather than by a primary
-- key, so no table needs special knowledge and a table with a non-integer or
-- composite key is covered like any other.
--
-- Output is stable across dump/restore: no clock- or OID-dependent values, and
-- the timezone is pinned because a timestamptz renders per-session.

\pset footer off
\pset format unaligned
\pset fieldsep '|'
SET TIME ZONE 'UTC';

-- One digest per user table, generated and then executed by \gexec.
SELECT format(
  'SELECT ''digest'' AS kind, %L AS name, '
  || 'coalesce(md5(string_agg(t::text, ''|'' ORDER BY t::text)), ''<empty>'') AS value '
  || 'FROM public.%I t',
  tablename, tablename)
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename
\gexec

-- Row counts, exact (not the pg_stat_user_tables estimate, which is only
-- populated by ANALYZE and would differ on a freshly restored cluster).
SELECT format(
  'SELECT ''rowcount'' AS kind, %L AS name, count(*)::text AS value FROM public.%I',
  tablename, tablename)
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename
\gexec

-- Sequence positions. A restore that forgot to advance these looks perfect
-- until the next INSERT collides on a primary key.
SELECT 'sequence' AS kind, sequencename AS name, coalesce(last_value::text, '<unread>') AS value
FROM pg_sequences
WHERE schemaname = 'public'
ORDER BY sequencename;

-- The set of tables itself, so a table that vanished entirely is a diff line
-- rather than a silently absent digest.
SELECT 'tablelist' AS kind, 'public' AS name, string_agg(tablename, ',' ORDER BY tablename) AS value
FROM pg_tables
WHERE schemaname = 'public';
