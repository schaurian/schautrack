-- Fixture for verifying a CloudNativePG migration moved everything, not just
-- the rows that are easy to move.
--
-- Deliberately exercises what a careless dump/restore loses:
--   * sequence positions (a reset sequence collides on the next INSERT)
--   * foreign keys across tables restored in the wrong order
--   * unicode text, jsonb, numeric precision and timestamptz
--   * a NULL-vs-empty-string distinction a sloppy round-trip flattens
BEGIN;

INSERT INTO users (email, password_hash, timezone, daily_goal, weight_unit, macros_enabled, macro_goals)
VALUES
  ('migrate-a@test.invalid', '$argon2id$v=19$m=65536,t=1,p=2$fake1', 'Europe/Berlin', 2200, 'kg',
   '{"protein": true, "carbs": true}'::jsonb, '{"protein": 150}'::jsonb),
  ('migrate-b@test.invalid', '$argon2id$v=19$m=65536,t=1,p=2$fake2', 'America/New_York', 1800, 'lbs',
   '{}'::jsonb, '{}'::jsonb),
  ('migrate-ue@test.invalid', '$argon2id$v=19$m=65536,t=1,p=2$fake3', 'Asia/Tokyo', 2000, 'kg',
   '{"fiber": true}'::jsonb, '{}'::jsonb);

INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name, protein_g, carbs_g, fat_g)
SELECT u.id,
       DATE '2026-08-01' + (n || ' days')::interval,
       400 + n,
       'Entry ' || n || ' — ümlaut & emoji 🥑',
       10 + n, 20 + n, 5 + n
FROM users u
CROSS JOIN generate_series(1, 40) AS n
WHERE u.email LIKE 'migrate-%';

INSERT INTO weight_entries (user_id, entry_date, weight, body_fat)
SELECT u.id, DATE '2026-08-01' + (n || ' days')::interval, 80.5 - (n * 0.1), 18.25 + (n * 0.01)
FROM users u CROSS JOIN generate_series(1, 20) AS n
WHERE u.email LIKE 'migrate-%';

INSERT INTO saved_foods (user_id, name, emoji, amount, protein_g, use_count)
SELECT u.id, 'Saved ' || n, '🍎', 100 * n, 5 * n, n
FROM users u CROSS JOIN generate_series(1, 12) AS n
WHERE u.email LIKE 'migrate-%';

INSERT INTO daily_notes (user_id, note_date, content)
SELECT u.id, DATE '2026-08-10', 'note with '' quote and ünicode'
FROM users u WHERE u.email = 'migrate-a@test.invalid';

-- NULL vs empty string: a round-trip that coerces one into the other is a bug.
INSERT INTO daily_notes (user_id, note_date, content)
SELECT u.id, DATE '2026-08-11', ''
FROM users u WHERE u.email = 'migrate-b@test.invalid';

-- Link row, so FK ordering matters on restore.
INSERT INTO account_links (requester_id, target_id, status, requester_label, target_label)
SELECT a.id, b.id, 'accepted', 'partner', 'me'
FROM users a, users b
WHERE a.email = 'migrate-a@test.invalid' AND b.email = 'migrate-b@test.invalid';

INSERT INTO todos (user_id, name, schedule, time_of_day, sort_order)
SELECT u.id, 'Todo ' || n, '{"days": [1,2,3,4,5]}'::jsonb, 'morning', n
FROM users u CROSS JOIN generate_series(1, 5) AS n
WHERE u.email = 'migrate-a@test.invalid';

COMMIT;
