package database

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestBuildPoolConfigMaxConnLifetimeNonZero is a regression guard for the
// staging crashloop introduced by the pgx v5.10.0 bump.
//
// As of pgx v5.10.0, pgxpool enforces MaxConnLifetime *at acquire time*
// (pgxpool.Pool.Acquire -> isExpired). A connection's expiry instant is
// computed at construction as:
//
//	maxAgeTime = time.Now().Add(MaxConnLifetime).Add(jitter)
//
// With MaxConnLifetime == 0 (which older pgx treated as "no maximum lifetime"),
// maxAgeTime equals the connection's birth instant, so isExpired() is true the
// moment the connection is acquired. Acquire then destroys the connection and
// retries maxConns+1 times before giving up with:
//
//	"pgxpool: too many failed attempts acquiring connection; likely bug in
//	 PrepareConn, BeforeAcquire, or ShouldPing hook"
//
// pool.Ping() hits this on startup, NewPool returns an error, and the whole
// app crashloops. The fix is to never set MaxConnLifetime to 0.
func TestBuildPoolConfigMaxConnLifetimeNonZero(t *testing.T) {
	cfg, err := buildPoolConfig("postgres://user:pass@localhost:5432/db")
	if err != nil {
		t.Fatalf("buildPoolConfig returned error: %v", err)
	}

	if cfg.MaxConnLifetime <= 0 {
		t.Fatalf("MaxConnLifetime must be > 0 to avoid the pgx v5.10.0 expire-at-acquire crashloop, got %v", cfg.MaxConnLifetime)
	}

	// A connection's forced max age must outlast the idle-reaping window,
	// otherwise connections would be recycled by age before idle reaping even
	// applies, which defeats the point of MaxConnIdleTime.
	if cfg.MaxConnLifetime <= cfg.MaxConnIdleTime {
		t.Errorf("MaxConnLifetime (%v) should exceed MaxConnIdleTime (%v)", cfg.MaxConnLifetime, cfg.MaxConnIdleTime)
	}
}

// TestNewPoolPingsRealDatabase exercises the full NewPool path (ParseConfig ->
// pool creation -> Ping) against a real PostgreSQL instance with the pinned pgx
// version. It directly reproduces the staging crashloop: with the buggy
// MaxConnLifetime == 0 config under pgx v5.10.0 this Ping fails; with the fix it
// succeeds.
//
// Skipped unless TEST_DATABASE_URL is set, so it does not gate CI (which has no
// database). Run locally with, e.g.:
//
//	TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./internal/database/ -run TestNewPoolPingsRealDatabase -v
func TestNewPoolPingsRealDatabase(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := NewPool(ctx, url)
	if err != nil {
		t.Fatalf("NewPool failed to connect/ping real database: %v", err)
	}
	defer pool.Close()

	var one int
	if err := pool.QueryRow(ctx, "select 1").Scan(&one); err != nil {
		t.Fatalf("query against pool failed: %v", err)
	}
	if one != 1 {
		t.Fatalf("expected 1, got %d", one)
	}
}
