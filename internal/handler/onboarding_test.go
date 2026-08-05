package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
)

// TestOnboardingCompleteKeepsFirstTimestamp covers the WHERE clause on
// OnboardingHandler.Complete.
//
// Replaying the tour from Settings ends in this same endpoint, so an
// unconditional UPDATE would quietly re-stamp the column every replay and turn
// "when this account was onboarded" into "when they last watched the tour".
// Dismissing the tour must also be idempotent — the client fires the call
// without awaiting it.
//
// Skipped unless TEST_DATABASE_URL is set, matching internal/database's
// integration tests.
func TestOnboardingCompleteKeepsFirstTimestamp(t *testing.T) {
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

	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	const email = "onboarding-complete@handler.test"
	cleanup := func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, email) }
	cleanup()
	t.Cleanup(cleanup)

	var userID int
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, email_verified, onboarding_completed_at)
		 VALUES ($1, 'x', true, NULL) RETURNING id`, email).Scan(&userID); err != nil {
		t.Fatalf("seeding the user failed: %v", err)
	}

	h := &OnboardingHandler{Pool: pool}
	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/onboarding/complete", nil)
		req = req.WithContext(middleware.WithTestUser(ctx, &model.User{ID: userID, Email: email}))
		rec := httptest.NewRecorder()
		h.Complete(rec, req)
		return rec
	}

	rec := call()
	if rec.Code != http.StatusOK {
		t.Fatalf("first dismissal: status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("first dismissal returned non-JSON: %v", err)
	}
	if body["ok"] != true {
		t.Errorf("first dismissal body = %v, want ok:true", body)
	}

	var first *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT onboarding_completed_at FROM users WHERE id = $1`, userID).Scan(&first); err != nil {
		t.Fatalf("reading the timestamp back failed: %v", err)
	}
	if first == nil {
		t.Fatal("dismissing the tour left onboarding_completed_at NULL; it would open again on the next login")
	}

	// A replay from Settings lands here again. The recorded date must not move.
	if rec := call(); rec.Code != http.StatusOK {
		t.Fatalf("replay dismissal: status = %d, want 200", rec.Code)
	}

	var second *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT onboarding_completed_at FROM users WHERE id = $1`, userID).Scan(&second); err != nil {
		t.Fatalf("re-reading the timestamp failed: %v", err)
	}
	if second == nil {
		t.Fatal("replaying the tour cleared onboarding_completed_at")
	}
	if !second.Equal(*first) {
		t.Errorf("replaying the tour moved the timestamp from %v to %v; it must record the first completion", *first, *second)
	}
}
