-- A content fingerprint of a schautrack database, for proving a migration was
-- lossless.
--
-- Row counts alone are not proof: they survive a restore that silently dropped
-- a column's contents, coerced NULL to '', or truncated numeric precision. So
-- each table is reduced to an md5 over its ordered, fully-rendered rows, and the
-- sequence positions are reported alongside — a restore that forgets to advance
-- sequences looks perfect until the next INSERT collides on a primary key.
--
-- Output is stable across dump/restore: ordered by primary key, and no
-- clock- or OID-dependent values.
\pset footer off
\pset format unaligned
\pset fieldsep '|'

SELECT 'rowcount' AS kind, relname AS name, n_live_tup::text AS value
FROM pg_stat_user_tables
ORDER BY relname;

SELECT 'digest' AS kind, 'users' AS name,
       md5(string_agg(t::text, '|' ORDER BY id))::text AS value
FROM (SELECT id, email, password_hash, daily_goal, timezone, weight_unit,
             macros_enabled, macro_goals, totp_enabled, email_verified
      FROM users) t;

SELECT 'digest', 'calorie_entries',
       md5(string_agg(t::text, '|' ORDER BY id))
FROM (SELECT id, user_id, entry_date, amount, entry_name,
             protein_g, carbs_g, fat_g, fiber_g, sugar_g
      FROM calorie_entries) t;

SELECT 'digest', 'weight_entries',
       md5(string_agg(t::text, '|' ORDER BY id))
FROM (SELECT id, user_id, entry_date, weight, body_fat FROM weight_entries) t;

SELECT 'digest', 'saved_foods',
       md5(string_agg(t::text, '|' ORDER BY id))
FROM (SELECT id, user_id, name, emoji, amount, protein_g, use_count FROM saved_foods) t;

SELECT 'digest', 'daily_notes',
       md5(string_agg(t::text, '|' ORDER BY id))
FROM (SELECT id, user_id, note_date, content FROM daily_notes) t;

SELECT 'digest', 'account_links',
       md5(string_agg(t::text, '|' ORDER BY id))
FROM (SELECT id, requester_id, target_id, status, requester_label, target_label
      FROM account_links) t;

SELECT 'digest', 'todos',
       md5(string_agg(t::text, '|' ORDER BY id))
FROM (SELECT id, user_id, name, schedule, time_of_day, sort_order, archived FROM todos) t;

-- NULL and '' must stay distinguishable.
SELECT 'nullcheck', 'daily_notes_null_vs_empty',
       count(*) FILTER (WHERE content IS NULL)::text || '/' ||
       count(*) FILTER (WHERE content = '')::text
FROM daily_notes;

-- Sequence positions. last_value must be >= max(id), or the next insert fails.
SELECT 'sequence', s.relname,
       (SELECT last_value FROM pg_sequences q
        WHERE q.schemaname = 'public' AND q.sequencename = s.relname)::text
FROM pg_class s
WHERE s.relkind = 'S' AND s.relnamespace = 'public'::regnamespace
ORDER BY s.relname;

-- Applied data migrations: the app must not try to re-run them post-cutover.
SELECT 'datamigration', name, 'applied' FROM schema_data_migrations ORDER BY name;
