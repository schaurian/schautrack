CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  daily_goal INTEGER,
  totp_secret TEXT,
  totp_enabled BOOLEAN DEFAULT FALSE,
  email_verified BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS calorie_entries (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  entry_date DATE NOT NULL DEFAULT CURRENT_DATE,
  amount INTEGER NOT NULL CHECK (amount >= -9999 AND amount <= 9999),
  entry_name TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS calorie_entries_user_date_idx ON calorie_entries (user_id, entry_date);

CREATE TABLE IF NOT EXISTS account_links (
  id SERIAL PRIMARY KEY,
  requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('pending', 'accepted')),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT account_links_not_self CHECK (requester_id <> target_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS account_links_pair_idx
  ON account_links (LEAST(requester_id, target_id), GREATEST(requester_id, target_id));

CREATE INDEX IF NOT EXISTS account_links_requester_idx ON account_links (requester_id);
CREATE INDEX IF NOT EXISTS account_links_target_idx ON account_links (target_id);
CREATE INDEX IF NOT EXISTS account_links_status_idx ON account_links (status);

CREATE TABLE IF NOT EXISTS "session" (
  "sid" VARCHAR NOT NULL,
  "sess" JSON NOT NULL,
  "expire" TIMESTAMP(6) NOT NULL,
  CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
);

CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");

CREATE TABLE IF NOT EXISTS weight_entries (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  entry_date DATE NOT NULL,
  weight NUMERIC(6, 2) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT weight_entries_positive CHECK (weight > 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS weight_unique_per_day_idx ON weight_entries (user_id, entry_date);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx ON password_reset_tokens (user_id);
CREATE INDEX IF NOT EXISTS password_reset_tokens_expires_idx ON password_reset_tokens (expires_at);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS email_verification_tokens_user_idx ON email_verification_tokens (user_id);
CREATE INDEX IF NOT EXISTS email_verification_tokens_expires_idx ON email_verification_tokens (expires_at);

CREATE TABLE IF NOT EXISTS admin_settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS todos (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  schedule JSONB NOT NULL DEFAULT '{"type":"daily"}',
  time_of_day TEXT,
  sort_order INTEGER DEFAULT 0,
  archived BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS todos_user_idx ON todos (user_id);

CREATE TABLE IF NOT EXISTS todo_completions (
  id SERIAL PRIMARY KEY,
  todo_id INTEGER NOT NULL REFERENCES todos(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  completion_date DATE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS todo_completions_unique_idx ON todo_completions (todo_id, completion_date);
CREATE INDEX IF NOT EXISTS todo_completions_user_date_idx ON todo_completions (user_id, completion_date);

CREATE TABLE IF NOT EXISTS invite_codes (
  id SERIAL PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  email TEXT,
  created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  used_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
  used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS invite_codes_code_idx ON invite_codes (code);

CREATE TABLE IF NOT EXISTS totp_backup_codes (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS totp_backup_codes_user_idx ON totp_backup_codes (user_id);

CREATE TABLE IF NOT EXISTS daily_notes (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  note_date DATE NOT NULL,
  content TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS daily_notes_user_date_idx ON daily_notes (user_id, note_date);

-- Additional user columns (added via Go migrations in internal/database/migrations.go)
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS notes_enabled BOOLEAN DEFAULT FALSE;
-- These are documented here for reference but applied by ensureUserPrefsSchema(), ensureAIKeysSchema(), and ensureMacroSchema()
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS todos_enabled BOOLEAN DEFAULT FALSE;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone TEXT;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS weight_unit TEXT DEFAULT 'kg';
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone_manual BOOLEAN DEFAULT FALSE;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS openai_api_key TEXT;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS claude_api_key TEXT;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS preferred_ai_provider TEXT DEFAULT 'openai';
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS macros_enabled JSONB DEFAULT '{}';
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS macro_goals JSONB DEFAULT '{}';
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS goal_threshold INTEGER DEFAULT 10;
--   goal_threshold: percentage (0-100) above which a goal violation turns red instead of yellow.
--   macro_goals JSONB shape: { "calories": 2000, "calories_mode": "limit", "protein": 150, "protein_mode": "target", "carbs": 200, "carbs_mode": "limit" }
--   Goal values are integers (grams, or kcal for calories). Mode values are "limit" (stay under) or "target" (try to reach).
--   Note: calorie goal was migrated from the legacy daily_goal column into macro_goals.calories.
--   Missing _mode keys fall back to defaults in internal/service/macros.go MacroGoalModes.
-- ALTER TABLE calorie_entries ADD COLUMN IF NOT EXISTS protein_g INTEGER CHECK (protein_g >= 0 AND protein_g <= 999);
-- ALTER TABLE calorie_entries ADD COLUMN IF NOT EXISTS carbs_g INTEGER CHECK (carbs_g >= 0 AND carbs_g <= 999);
-- ALTER TABLE calorie_entries ADD COLUMN IF NOT EXISTS fat_g INTEGER CHECK (fat_g >= 0 AND fat_g <= 999);
-- ALTER TABLE calorie_entries ADD COLUMN IF NOT EXISTS fiber_g INTEGER CHECK (fiber_g >= 0 AND fiber_g <= 999);
-- ALTER TABLE calorie_entries ADD COLUMN IF NOT EXISTS sugar_g INTEGER CHECK (sugar_g >= 0 AND sugar_g <= 999);
