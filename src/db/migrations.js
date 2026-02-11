const { pool } = require('./pool');

// Create base tables that other migrations depend on
async function ensureBaseSchema() {
  // Create users table first (many other tables reference it)
  await pool.query(`
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
  `);

  // Create calorie_entries table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS calorie_entries (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      entry_date DATE NOT NULL DEFAULT CURRENT_DATE,
      amount INTEGER NOT NULL,
      entry_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Create session table for express-session
  await pool.query(`
    CREATE TABLE IF NOT EXISTS "session" (
      "sid" VARCHAR NOT NULL,
      "sess" JSON NOT NULL,
      "expire" TIMESTAMP(6) NOT NULL,
      CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
    );
    CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
  `);
}

async function ensureAccountLinksSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS account_links (
      id SERIAL PRIMARY KEY,
      requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      target_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL CHECK (status IN ('pending', 'accepted')),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      CONSTRAINT account_links_not_self CHECK (requester_id <> target_id)
    );
    ALTER TABLE account_links
      ADD COLUMN IF NOT EXISTS label TEXT,
      ADD COLUMN IF NOT EXISTS requester_label TEXT,
      ADD COLUMN IF NOT EXISTS target_label TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS account_links_pair_idx
      ON account_links (LEAST(requester_id, target_id), GREATEST(requester_id, target_id));
    CREATE INDEX IF NOT EXISTS account_links_requester_idx ON account_links (requester_id);
    CREATE INDEX IF NOT EXISTS account_links_target_idx ON account_links (target_id);
    CREATE INDEX IF NOT EXISTS account_links_status_idx ON account_links (status);
    UPDATE account_links
       SET requester_label = COALESCE(requester_label, label),
           target_label = COALESCE(target_label, label)
     WHERE (requester_label IS NULL OR target_label IS NULL) AND label IS NOT NULL;
  `);
}

async function ensureWeightEntriesSchema() {
  await pool.query(`
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
  `);
}

async function ensureUserPrefsSchema() {
  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS timezone TEXT,
      ADD COLUMN IF NOT EXISTS weight_unit TEXT,
      ADD COLUMN IF NOT EXISTS timezone_manual BOOLEAN DEFAULT FALSE;
    ALTER TABLE users
      ALTER COLUMN weight_unit SET DEFAULT 'kg';
    UPDATE users SET weight_unit = 'kg' WHERE weight_unit IS NULL;
  `);
}

async function ensureCalorieEntriesSchema() {
  await pool.query(`
    ALTER TABLE calorie_entries
      ADD COLUMN IF NOT EXISTS entry_name TEXT,
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
  `);
}

async function ensurePasswordResetSchema() {
  await pool.query(`
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
  `);
}

async function ensureEmailVerificationSchema() {
  // First ensure the users table has created_at column
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
  `);

  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;
  `);

  await pool.query(`
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
  `);

  // Add new_email column for email change functionality
  await pool.query(`
    ALTER TABLE email_verification_tokens ADD COLUMN IF NOT EXISTS new_email TEXT;
  `);

  // Mark unverified users as verified if they have no pending verification token
  // This handles users created before email verification was added
  await pool.query(`
    UPDATE users SET email_verified = TRUE
    WHERE email_verified = FALSE
      AND id NOT IN (
        SELECT DISTINCT user_id FROM email_verification_tokens
        WHERE used = FALSE AND expires_at > NOW()
      )
  `);
}

async function ensureAdminSettingsSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

async function ensureAIKeysSchema() {
  // Add new unified columns
  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS openai_api_key TEXT,
      ADD COLUMN IF NOT EXISTS claude_api_key TEXT,
      ADD COLUMN IF NOT EXISTS preferred_ai_provider TEXT DEFAULT 'openai',
      ADD COLUMN IF NOT EXISTS ai_key TEXT,
      ADD COLUMN IF NOT EXISTS ai_endpoint TEXT;
  `);

  // Migrate existing keys to unified field
  await pool.query(`
    UPDATE users
    SET ai_key = CASE
      WHEN preferred_ai_provider = 'claude' THEN claude_api_key
      ELSE openai_api_key
    END
    WHERE (openai_api_key IS NOT NULL OR claude_api_key IS NOT NULL)
      AND ai_key IS NULL;
  `);
}

async function ensureAIUsageSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ai_usage (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      usage_date DATE NOT NULL DEFAULT CURRENT_DATE,
      request_count INTEGER NOT NULL DEFAULT 0,
      CONSTRAINT ai_usage_unique UNIQUE (user_id, usage_date)
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS ai_usage_user_date_idx ON ai_usage (user_id, usage_date);
  `);
}

// Retry schema initialization with exponential backoff
async function initSchemaWithRetry(maxRetries = 10, initialDelay = 1000) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      // First create base tables (users, calorie_entries, session)
      // These must exist before other migrations that ALTER or reference them
      await ensureBaseSchema();

      // Then run all other migrations in parallel
      await Promise.all([
        ensureAccountLinksSchema(),
        ensureWeightEntriesSchema(),
        ensureUserPrefsSchema(),
        ensureCalorieEntriesSchema(),
        ensurePasswordResetSchema(),
        ensureEmailVerificationSchema(),
        ensureAdminSettingsSchema(),
        ensureAIKeysSchema(),
        ensureAIUsageSchema()
      ]);
      console.log('Schema initialization successful');
      return;
    } catch (err) {
      const delay = initialDelay * Math.pow(2, attempt - 1);
      console.error(`Schema init failed (attempt ${attempt}/${maxRetries}):`, err.message);
      if (attempt < maxRetries) {
        console.log(`Retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      } else {
        console.error('Schema initialization failed after all retries. App will start but may have issues.');
      }
    }
  }
}

module.exports = {
  initSchemaWithRetry,
  ensureBaseSchema,
  ensureAccountLinksSchema,
  ensureWeightEntriesSchema,
  ensureUserPrefsSchema,
  ensureCalorieEntriesSchema,
  ensurePasswordResetSchema,
  ensureEmailVerificationSchema,
  ensureAdminSettingsSchema,
  ensureAIKeysSchema,
  ensureAIUsageSchema
};