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
  amount INTEGER NOT NULL,
  entry_name TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

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
  token TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx ON password_reset_tokens (user_id);
CREATE INDEX IF NOT EXISTS password_reset_tokens_expires_idx ON password_reset_tokens (expires_at);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT NOT NULL,
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

-- Additional user columns (added via migration in server.js)
-- These are documented here for reference but applied by ensureUserPrefsSchema() and ensureAIKeysSchema()
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone TEXT;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS weight_unit TEXT DEFAULT 'kg';
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS timezone_manual BOOLEAN DEFAULT FALSE;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS openai_api_key TEXT;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS claude_api_key TEXT;
-- ALTER TABLE users ADD COLUMN IF NOT EXISTS preferred_ai_provider TEXT DEFAULT 'openai';
