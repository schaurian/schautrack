package database

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRetrySchemaInitReturnsLastError is a regression guard for the fail-fast
// fix: once all retries are exhausted, retrySchemaInit must RETURN the last
// error (not nil). Returning nil made the caller's error check dead code, so
// the app booted against a partial/missing schema.
func TestRetrySchemaInitReturnsLastError(t *testing.T) {
	boom := errors.New("boom")
	calls := 0

	err := retrySchemaInit(3, 0, func() error {
		calls++
		return boom
	})

	if !errors.Is(err, boom) {
		t.Fatalf("expected the last error to propagate, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
}

// TestRetrySchemaInitSucceedsAfterTransientFailures verifies the loop stops and
// returns nil on the first success, without exhausting the remaining retries.
func TestRetrySchemaInitSucceedsAfterTransientFailures(t *testing.T) {
	calls := 0

	err := retrySchemaInit(5, 0, func() error {
		calls++
		if calls < 3 {
			return errors.New("transient")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected nil after eventual success, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected to stop at the 3rd (successful) attempt, got %d calls", calls)
	}
}

// TestRunAllMigrationsIdempotentBodyProfileAndWeightGoals verifies that the
// body-metric columns on users and the new weight_goals table are created,
// and that running all migrations a second time is a no-op (no error) —
// guarding against non-idempotent DDL (e.g. duplicate CHECK constraints).
//
// Skipped unless TEST_DATABASE_URL is set, so it does not gate CI (which has
// no database). Run locally with, e.g.:
//
//	TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./internal/database/ -run TestRunAllMigrationsIdempotentBodyProfileAndWeightGoals -v
func TestRunAllMigrationsIdempotentBodyProfileAndWeightGoals(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := NewPool(ctx, url)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer pool.Close()

	if err := runAllMigrations(ctx, pool); err != nil {
		t.Fatalf("first runAllMigrations failed: %v", err)
	}
	if err := runAllMigrations(ctx, pool); err != nil {
		t.Fatalf("second runAllMigrations (idempotency check) failed: %v", err)
	}

	var columnExists bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'users' AND column_name = 'height_cm'
		)`).Scan(&columnExists); err != nil {
		t.Fatalf("querying information_schema.columns failed: %v", err)
	}
	if !columnExists {
		t.Error("expected users.height_cm column to exist")
	}

	var tableExists bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM information_schema.tables
			WHERE table_name = 'weight_goals' AND table_schema = 'public'
		)`).Scan(&tableExists); err != nil {
		t.Fatalf("querying information_schema.tables failed: %v", err)
	}
	if !tableExists {
		t.Error("expected weight_goals table to exist")
	}
}

func TestAccountLinksShareColumns(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	// Running twice must be clean (idempotent).
	if err := ensureAccountLinksSchema(ctx, pool); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := ensureAccountLinksSchema(ctx, pool); err != nil {
		t.Fatalf("second run: %v", err)
	}

	for _, col := range []string{"requester_shares", "target_shares"} {
		var exists bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_name='account_links' AND column_name=$1 AND data_type='jsonb')`, col).Scan(&exists)
		if err != nil || !exists {
			t.Fatalf("column %s missing (err=%v)", col, err)
		}
	}
}
