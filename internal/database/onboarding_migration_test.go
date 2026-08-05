package database

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestOnboardingBackfillRunsOnlyOnColumnCreation pins the one thing
// ensureOnboardingSchema can get wrong.
//
// The welcome tour opens whenever onboarding_completed_at IS NULL. A plain
// "ADD COLUMN IF NOT EXISTS" would therefore pop the tour in front of every
// existing account on the upgrade that ships it, and a re-running unconditional
// backfill would silently mark brand-new accounts as onboarded — cancelling the
// feature for exactly the people it exists for. The migration threads that
// needle by backfilling only when it is the one that created the column, so
// both halves are asserted here.
//
// Skipped unless TEST_DATABASE_URL is set, matching the other integration
// tests in this package. Run locally with, e.g.:
//
//	TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./internal/database/ -run TestOnboardingBackfill -v
func TestOnboardingBackfillRunsOnlyOnColumnCreation(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	if err := runAllMigrations(ctx, pool); err != nil {
		t.Fatalf("runAllMigrations: %v", err)
	}

	const legacyEmail = "onboarding-legacy@migration.test"
	const freshEmail = "onboarding-fresh@migration.test"
	cleanup := func() {
		pool.Exec(ctx, `DELETE FROM users WHERE email = ANY($1)`, []string{legacyEmail, freshEmail})
	}
	cleanup()
	t.Cleanup(cleanup)

	// Rewind to a pre-feature schema so the migration has to create the column.
	if _, err := pool.Exec(ctx, `ALTER TABLE users DROP COLUMN IF EXISTS onboarding_completed_at`); err != nil {
		t.Fatalf("dropping the column to simulate an old schema failed: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`INSERT INTO users (email, password_hash, email_verified) VALUES ($1, 'x', true)`,
		legacyEmail); err != nil {
		t.Fatalf("seeding the pre-existing user failed: %v", err)
	}

	// First run: creates the column, so the account that predates the feature
	// must come out already onboarded.
	if err := ensureOnboardingSchema(ctx, pool); err != nil {
		t.Fatalf("ensureOnboardingSchema (creating run): %v", err)
	}
	var legacyCompletedAt *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT onboarding_completed_at FROM users WHERE email = $1`, legacyEmail).Scan(&legacyCompletedAt); err != nil {
		t.Fatalf("reading the pre-existing user back failed: %v", err)
	}
	if legacyCompletedAt == nil {
		t.Error("a user that existed before the migration was left un-onboarded; the tour would open for them on upgrade")
	}

	// A signup after the feature landed starts at NULL — it should see the tour.
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (email, password_hash, email_verified) VALUES ($1, 'x', true)`,
		freshEmail); err != nil {
		t.Fatalf("seeding the new user failed: %v", err)
	}

	// Second run (every subsequent boot): the column already exists, so nothing
	// may be backfilled.
	if err := ensureOnboardingSchema(ctx, pool); err != nil {
		t.Fatalf("ensureOnboardingSchema (idempotent run): %v", err)
	}
	var freshCompletedAt *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT onboarding_completed_at FROM users WHERE email = $1`, freshEmail).Scan(&freshCompletedAt); err != nil {
		t.Fatalf("reading the new user back failed: %v", err)
	}
	if freshCompletedAt != nil {
		t.Errorf("a user created after the migration was marked onboarded at %v; they would never see the tour", *freshCompletedAt)
	}
}
