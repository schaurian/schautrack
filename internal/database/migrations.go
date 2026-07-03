package database

import (
	"context"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func withTransaction(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func ensureBaseSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS users (
				id SERIAL PRIMARY KEY,
				email TEXT NOT NULL UNIQUE,
				password_hash TEXT NOT NULL,
				daily_goal INTEGER,
				totp_secret TEXT,
				totp_enabled BOOLEAN DEFAULT FALSE,
				email_verified BOOLEAN DEFAULT FALSE,
				created_at TIMESTAMPTZ DEFAULT NOW()
			)`)
		if err != nil {
			return err
		}

		_, err = tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS calorie_entries (
				id SERIAL PRIMARY KEY,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				entry_date DATE NOT NULL DEFAULT CURRENT_DATE,
				amount INTEGER NOT NULL,
				entry_name TEXT,
				created_at TIMESTAMPTZ DEFAULT NOW()
			)`)
		if err != nil {
			return err
		}

		_, err = tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS "session" (
				"sid" VARCHAR NOT NULL,
				"sess" JSON NOT NULL,
				"expire" TIMESTAMP(6) NOT NULL,
				CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
			);
			CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire")`)
		return err
	})
}

func ensureAccountLinksSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
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
				WHERE (requester_label IS NULL OR target_label IS NULL) AND label IS NOT NULL`)
		return err
	})
}

func ensureWeightEntriesSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS weight_entries (
				id SERIAL PRIMARY KEY,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				entry_date DATE NOT NULL,
				weight NUMERIC(6, 2) NOT NULL,
				created_at TIMESTAMPTZ DEFAULT NOW(),
				updated_at TIMESTAMPTZ DEFAULT NOW(),
				CONSTRAINT weight_entries_positive CHECK (weight > 0)
			);
			CREATE UNIQUE INDEX IF NOT EXISTS weight_unique_per_day_idx ON weight_entries (user_id, entry_date)`)
		return err
	})
}

func ensureUserPrefsSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			ALTER TABLE users
				ADD COLUMN IF NOT EXISTS timezone TEXT,
				ADD COLUMN IF NOT EXISTS weight_unit TEXT,
				ADD COLUMN IF NOT EXISTS timezone_manual BOOLEAN DEFAULT FALSE;
			ALTER TABLE users
				ALTER COLUMN weight_unit SET DEFAULT 'kg';
			UPDATE users SET weight_unit = 'kg' WHERE weight_unit IS NULL`)
		return err
	})
}

func ensureCalorieEntriesSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			ALTER TABLE calorie_entries
				ADD COLUMN IF NOT EXISTS entry_name TEXT,
				ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
			CREATE INDEX IF NOT EXISTS calorie_entries_user_date_idx ON calorie_entries (user_id, entry_date);
			DO $$ BEGIN
				ALTER TABLE calorie_entries ADD CONSTRAINT calorie_entries_amount_range CHECK (amount >= -9999 AND amount <= 9999);
			EXCEPTION WHEN duplicate_object THEN NULL;
			END $$`)
		return err
	})
}

func ensurePasswordResetSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
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
			CREATE UNIQUE INDEX IF NOT EXISTS password_reset_tokens_token_idx ON password_reset_tokens (token)`)
		return err
	})
}

func ensureEmailVerificationSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()`)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE`)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
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
			CREATE UNIQUE INDEX IF NOT EXISTS email_verification_tokens_token_idx ON email_verification_tokens (token)`)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `ALTER TABLE email_verification_tokens ADD COLUMN IF NOT EXISTS new_email TEXT`)
		if err != nil {
			return err
		}

		// One-time DATA backfill: grandfather in existing users that predate
		// email verification (they have no pending token). This MUST run at most
		// once — re-running it on every boot flips email_verified=TRUE for any
		// user whose only tokens have since expired or been cleaned up by the
		// 15-min sweep, silently verifying emails nobody confirmed (an email-
		// verification bypass). A persistent marker row guards it. The DDL above
		// still runs every boot; only this UPDATE is gated.
		//
		// schema_data_migrations is created and read only here, so there is no
		// concurrent-CREATE race with the parallel ensureXxx migrations.
		_, err = tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS schema_data_migrations (
				name TEXT PRIMARY KEY,
				applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
			)`)
		if err != nil {
			return err
		}
		var backfillDone bool
		err = tx.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM schema_data_migrations WHERE name = 'email_verified_backfill'
			)`).Scan(&backfillDone)
		if err != nil {
			return err
		}
		if backfillDone {
			return nil
		}
		_, err = tx.Exec(ctx, `
			UPDATE users SET email_verified = TRUE
			WHERE email_verified = FALSE
				AND id NOT IN (
					SELECT DISTINCT user_id FROM email_verification_tokens
					WHERE used = FALSE AND expires_at > NOW()
				)`)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO schema_data_migrations (name) VALUES ('email_verified_backfill')
			ON CONFLICT (name) DO NOTHING`)
		return err
	})
}

func ensureAdminSettingsSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS admin_settings (
				key TEXT PRIMARY KEY,
				value TEXT,
				updated_at TIMESTAMPTZ DEFAULT NOW()
			)`)
		if err != nil {
			return err
		}
		// Migrate registration_mode → enable_registration
		_, err = tx.Exec(ctx, `
			INSERT INTO admin_settings (key, value, updated_at)
			SELECT 'enable_registration',
				CASE WHEN value = 'invite' THEN 'false' ELSE 'true' END,
				updated_at
			FROM admin_settings WHERE key = 'registration_mode'
			ON CONFLICT (key) DO NOTHING`)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM admin_settings WHERE key = 'registration_mode'`)
		return err
	})
}

func ensureAIKeysSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			ALTER TABLE users
				ADD COLUMN IF NOT EXISTS openai_api_key TEXT,
				ADD COLUMN IF NOT EXISTS claude_api_key TEXT,
				ADD COLUMN IF NOT EXISTS preferred_ai_provider TEXT DEFAULT 'openai',
				ADD COLUMN IF NOT EXISTS ai_key TEXT,
				ADD COLUMN IF NOT EXISTS ai_endpoint TEXT,
				ADD COLUMN IF NOT EXISTS ai_model TEXT,
				ADD COLUMN IF NOT EXISTS ai_daily_limit INTEGER`)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS ai_key_last4 TEXT`)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			UPDATE users
			SET ai_key = CASE
				WHEN preferred_ai_provider = 'claude' THEN claude_api_key
				ELSE openai_api_key
			END
			WHERE (openai_api_key IS NOT NULL OR claude_api_key IS NOT NULL)
				AND ai_key IS NULL`)
		return err
	})
}

func ensureAIUsageSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS ai_usage (
				id SERIAL PRIMARY KEY,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				usage_date DATE NOT NULL DEFAULT CURRENT_DATE,
				request_count INTEGER NOT NULL DEFAULT 0,
				CONSTRAINT ai_usage_unique UNIQUE (user_id, usage_date)
			);
			CREATE INDEX IF NOT EXISTS ai_usage_user_date_idx ON ai_usage (user_id, usage_date)`)
		return err
	})
}

func ensureMacroSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			ALTER TABLE users
				ADD COLUMN IF NOT EXISTS macros_enabled JSONB DEFAULT '{}',
				ADD COLUMN IF NOT EXISTS macro_goals JSONB DEFAULT '{}',
				ADD COLUMN IF NOT EXISTS goal_threshold INTEGER DEFAULT 10`)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			ALTER TABLE calorie_entries
				ADD COLUMN IF NOT EXISTS protein_g INTEGER,
				ADD COLUMN IF NOT EXISTS carbs_g INTEGER,
				ADD COLUMN IF NOT EXISTS fat_g INTEGER,
				ADD COLUMN IF NOT EXISTS fiber_g INTEGER,
				ADD COLUMN IF NOT EXISTS sugar_g INTEGER`)
		if err != nil {
			return err
		}

		// Add CHECK constraints for macro columns (idempotent: skip if already exists)
		macroChecks := []struct{ name, col string }{
			{"calorie_entries_protein_g_range", "protein_g"},
			{"calorie_entries_carbs_g_range", "carbs_g"},
			{"calorie_entries_fat_g_range", "fat_g"},
			{"calorie_entries_fiber_g_range", "fiber_g"},
			{"calorie_entries_sugar_g_range", "sugar_g"},
		}
		for _, c := range macroChecks {
			_, err = tx.Exec(ctx, fmt.Sprintf(`
				DO $$ BEGIN
					ALTER TABLE calorie_entries ADD CONSTRAINT %s CHECK (%s >= 0 AND %s <= 999);
				EXCEPTION WHEN duplicate_object THEN NULL;
				END $$`, c.name, c.col, c.col))
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func migrateCalorieGoalToMacroGoals(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE users
				SET macro_goals = jsonb_set(COALESCE(macro_goals, '{}'::jsonb), '{calories}', to_jsonb(daily_goal)),
					daily_goal = NULL
				WHERE daily_goal IS NOT NULL
					AND NOT (COALESCE(macro_goals, '{}'::jsonb) ? 'calories')`)
		return err
	})
}

func migrateAutoCalcCalories(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE users
				SET macros_enabled = macros_enabled || '{"auto_calc_calories": true}'::jsonb
				WHERE macros_enabled->>'protein' = 'true'
					AND macros_enabled->>'carbs' = 'true'
					AND macros_enabled->>'fat' = 'true'
					AND NOT (macros_enabled ? 'auto_calc_calories')`)
		return err
	})
}

func ensureTodosSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		// Rename from activities -> todos if upgrading
		var exists bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = 'activities' AND table_schema = 'public')`).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			if _, err := tx.Exec(ctx, `ALTER TABLE activities RENAME TO todos`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `ALTER TABLE activity_completions RENAME TO todo_completions`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `ALTER TABLE todo_completions RENAME COLUMN activity_id TO todo_id`); err != nil {
				return err
			}
		}

		// Rename user column if upgrading
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name = 'users' AND column_name = 'activities_enabled')`).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			if _, err := tx.Exec(ctx, `ALTER TABLE users RENAME COLUMN activities_enabled TO todos_enabled`); err != nil {
				return err
			}
		}

		_, err = tx.Exec(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS todos_enabled BOOLEAN DEFAULT FALSE`)
		if err != nil {
			return err
		}

		_, err = tx.Exec(ctx, `
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
			CREATE INDEX IF NOT EXISTS todos_user_idx ON todos (user_id)`)
		if err != nil {
			return err
		}

		_, err = tx.Exec(ctx, `ALTER TABLE todos ADD COLUMN IF NOT EXISTS time_of_day TEXT`)
		if err != nil {
			return err
		}

		_, err = tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS todo_completions (
				id SERIAL PRIMARY KEY,
				todo_id INTEGER NOT NULL REFERENCES todos(id) ON DELETE CASCADE,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				completion_date DATE NOT NULL,
				created_at TIMESTAMPTZ DEFAULT NOW()
			);
			CREATE UNIQUE INDEX IF NOT EXISTS todo_completions_unique_idx ON todo_completions (todo_id, completion_date);
			CREATE INDEX IF NOT EXISTS todo_completions_user_date_idx ON todo_completions (user_id, completion_date)`)
		if err != nil {
			return err
		}

		// Add FK if missing (for databases created before this migration)
		_, err = tx.Exec(ctx, `
			DO $$ BEGIN
				IF NOT EXISTS (
					SELECT 1 FROM information_schema.table_constraints
					WHERE constraint_name = 'todo_completions_user_id_fkey'
					AND table_name = 'todo_completions'
				) THEN
					ALTER TABLE todo_completions
						ADD CONSTRAINT todo_completions_user_id_fkey
						FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
				END IF;
			END $$`)
		return err
	})
}

func ensureInviteSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
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
			CREATE INDEX IF NOT EXISTS invite_codes_code_idx ON invite_codes (code)`)
		return err
	})
}

func ensureBackupCodesSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS totp_backup_codes (
				id SERIAL PRIMARY KEY,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				code_hash TEXT NOT NULL,
				used BOOLEAN DEFAULT FALSE,
				created_at TIMESTAMPTZ DEFAULT NOW()
			);
			CREATE INDEX IF NOT EXISTS totp_backup_codes_user_idx ON totp_backup_codes (user_id)`)
		return err
	})
}

func ensureDailyNotesSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `ALTER TABLE users ADD COLUMN IF NOT EXISTS notes_enabled BOOLEAN DEFAULT FALSE`)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS daily_notes (
				id SERIAL PRIMARY KEY,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				note_date DATE NOT NULL,
				content TEXT NOT NULL DEFAULT '',
				created_at TIMESTAMPTZ DEFAULT NOW(),
				updated_at TIMESTAMPTZ DEFAULT NOW()
			);
			CREATE UNIQUE INDEX IF NOT EXISTS daily_notes_user_date_idx ON daily_notes (user_id, note_date)`)
		return err
	})
}

// InitSchemaWithRetry runs all migrations with exponential backoff.
func InitSchemaWithRetry(ctx context.Context, pool *pgxpool.Pool, maxRetries int) error {
	return retrySchemaInit(maxRetries, time.Second, func() error {
		return runAllMigrations(ctx, pool)
	})
}

// retrySchemaInit runs `run` up to maxRetries times with exponential backoff.
// It returns nil on the first success, or the LAST error once all attempts are
// exhausted. Returning that error (instead of nil) lets the caller fail fast:
// serving traffic against a partial/missing schema causes every query to 500,
// while /api/health only pings the DB — so probes stay green and a broken pod
// would replace a healthy one under RollingUpdate maxUnavailable:0.
func retrySchemaInit(maxRetries int, initialDelay time.Duration, run func() error) error {
	if maxRetries == 0 {
		maxRetries = 10
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		lastErr = run()
		if lastErr == nil {
			log.Println("Schema initialization successful")
			return nil
		}

		delay := time.Duration(float64(initialDelay) * math.Pow(2, float64(attempt-1)))
		log.Printf("Schema init failed (attempt %d/%d): %v", attempt, maxRetries, lastErr)
		if attempt < maxRetries {
			log.Printf("Retrying in %v...", delay)
			time.Sleep(delay)
		} else {
			log.Println("Schema initialization failed after all retries; aborting startup.")
		}
	}
	return lastErr
}

func ensureOIDCAccountsSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS user_oidc_accounts (
				id SERIAL PRIMARY KEY,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				provider TEXT NOT NULL,
				subject TEXT NOT NULL,
				email TEXT,
				created_at TIMESTAMPTZ DEFAULT NOW(),
				UNIQUE(provider, subject)
			)`)
		if err != nil {
			return err
		}
		// Allow OIDC-only users without a password
		_, err = tx.Exec(ctx, `
			ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL`)
		return err
	})
}

func ensurePasskeysSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS user_passkeys (
				id SERIAL PRIMARY KEY,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				credential_id BYTEA NOT NULL UNIQUE,
				public_key BYTEA NOT NULL,
				attestation_type TEXT,
				transports TEXT,
				name TEXT NOT NULL,
				sign_count INTEGER DEFAULT 0,
				aaguid BYTEA,
				created_at TIMESTAMPTZ DEFAULT NOW(),
				last_used_at TIMESTAMPTZ
			)`); err != nil {
			return err
		}
		// Backup Eligible / Backup State flags (WebAuthn L3). Stored at registration
		// and re-applied to the Credential at login so go-webauthn's flag-consistency
		// check passes (otherwise login fails with "Backup Eligible flag inconsistency").
		_, err := tx.Exec(ctx, `
			ALTER TABLE user_passkeys
				ADD COLUMN IF NOT EXISTS backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
				ADD COLUMN IF NOT EXISTS backup_state    BOOLEAN NOT NULL DEFAULT FALSE`)
		return err
	})
}

func ensureSavedFoodsSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS saved_foods (
				id SERIAL PRIMARY KEY,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				name TEXT NOT NULL,
				emoji TEXT,
				amount INTEGER,
				protein_g INTEGER,
				carbs_g INTEGER,
				fat_g INTEGER,
				fiber_g INTEGER,
				sugar_g INTEGER,
				use_count INTEGER NOT NULL DEFAULT 0,
				last_used_at TIMESTAMPTZ,
				shared BOOLEAN NOT NULL DEFAULT FALSE,
				created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
				updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
			)`); err != nil {
			return err
		}

		checks := []struct{ name, expr string }{
			{"saved_foods_amount_range", "amount IS NULL OR (amount >= -9999 AND amount <= 9999)"},
			{"saved_foods_protein_range", "protein_g IS NULL OR (protein_g >= 0 AND protein_g <= 999)"},
			{"saved_foods_carbs_range", "carbs_g IS NULL OR (carbs_g >= 0 AND carbs_g <= 999)"},
			{"saved_foods_fat_range", "fat_g IS NULL OR (fat_g >= 0 AND fat_g <= 999)"},
			{"saved_foods_fiber_range", "fiber_g IS NULL OR (fiber_g >= 0 AND fiber_g <= 999)"},
			{"saved_foods_sugar_range", "sugar_g IS NULL OR (sugar_g >= 0 AND sugar_g <= 999)"},
		}
		for _, c := range checks {
			if _, err := tx.Exec(ctx, fmt.Sprintf(`
				DO $$ BEGIN
					ALTER TABLE saved_foods ADD CONSTRAINT %s CHECK (%s);
				EXCEPTION WHEN duplicate_object THEN NULL;
				END $$`, c.name, c.expr)); err != nil {
				return err
			}
		}

		if _, err := tx.Exec(ctx, `
			CREATE UNIQUE INDEX IF NOT EXISTS saved_foods_user_name_idx
				ON saved_foods (user_id, lower(name));
			CREATE INDEX IF NOT EXISTS saved_foods_rank_idx
				ON saved_foods (user_id, use_count DESC, last_used_at DESC NULLS LAST);
			CREATE INDEX IF NOT EXISTS saved_foods_shared_idx
				ON saved_foods (user_id) WHERE shared = TRUE`); err != nil {
			return err
		}
		return nil
	})
}

func ensureAuditLogSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		// user_id is nullable + ON DELETE SET NULL so audit history survives
		// account deletion (you still want to know "user X deleted their
		// account" after the row is gone). action is a stable short code
		// (e.g. "password_changed"); metadata is freeform jsonb for context
		// like the old/new email on email change.
		if _, err := tx.Exec(ctx, `
			CREATE TABLE IF NOT EXISTS audit_log (
				id          BIGSERIAL PRIMARY KEY,
				user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
				action      TEXT NOT NULL,
				ip          TEXT,
				user_agent  TEXT,
				metadata    JSONB,
				created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
			)`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`CREATE INDEX IF NOT EXISTS audit_log_user_created_idx ON audit_log (user_id, created_at DESC)`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`CREATE INDEX IF NOT EXISTS audit_log_action_created_idx ON audit_log (action, created_at DESC)`)
		return err
	})
}

func runAllMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	// Base tables first (others depend on them)
	if err := ensureBaseSchema(ctx, pool); err != nil {
		return fmt.Errorf("base schema: %w", err)
	}

	// Parallel migrations
	type migrationResult struct {
		name string
		err  error
	}
	migrations := []struct {
		name string
		fn   func(context.Context, *pgxpool.Pool) error
	}{
		{"account_links", ensureAccountLinksSchema},
		{"weight_entries", ensureWeightEntriesSchema},
		{"user_prefs", ensureUserPrefsSchema},
		{"calorie_entries", ensureCalorieEntriesSchema},
		{"password_reset", ensurePasswordResetSchema},
		{"email_verification", ensureEmailVerificationSchema},
		{"admin_settings", ensureAdminSettingsSchema},
		{"ai_keys", ensureAIKeysSchema},
		{"ai_usage", ensureAIUsageSchema},
		{"macros", ensureMacroSchema},
		{"oidc_accounts", ensureOIDCAccountsSchema},
		{"passkeys", ensurePasskeysSchema},
		{"audit_log", ensureAuditLogSchema},
		{"saved_foods", ensureSavedFoodsSchema},
	}

	results := make(chan migrationResult, len(migrations))
	for _, m := range migrations {
		go func(name string, fn func(context.Context, *pgxpool.Pool) error) {
			results <- migrationResult{name: name, err: fn(ctx, pool)}
		}(m.name, m.fn)
	}

	for range migrations {
		r := <-results
		if r.err != nil {
			return fmt.Errorf("migration %s: %w", r.name, r.err)
		}
	}

	// Dependent migrations
	if err := ensureTodosSchema(ctx, pool); err != nil {
		return fmt.Errorf("todos schema: %w", err)
	}
	if err := ensureDailyNotesSchema(ctx, pool); err != nil {
		return fmt.Errorf("daily_notes schema: %w", err)
	}
	if err := ensureBackupCodesSchema(ctx, pool); err != nil {
		return fmt.Errorf("backup_codes schema: %w", err)
	}
	if err := ensureInviteSchema(ctx, pool); err != nil {
		return fmt.Errorf("invite schema: %w", err)
	}

	// Data migrations
	if err := migrateCalorieGoalToMacroGoals(ctx, pool); err != nil {
		return fmt.Errorf("calorie goal migration: %w", err)
	}
	if err := migrateAutoCalcCalories(ctx, pool); err != nil {
		return fmt.Errorf("auto calc calories migration: %w", err)
	}

	return nil
}
