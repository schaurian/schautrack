package handler

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"schautrack/internal/service"
)

// RequireAPIToken's rejection branches, exercised against real token rows
// rather than against a nil pool. api-tokens.spec.ts covers minting and
// revoking through the session UI; none of it checks what /api/v1 does with the
// resulting token.

// TestV1RejectsMalformedAuthorizationHeaders covers ParseBearer through the
// middleware, including the case that must NOT be rejected: RFC 7235 makes the
// scheme name case-insensitive.
func TestV1RejectsMalformedAuthorizationHeaders(t *testing.T) {
	e := newV1Env(t)
	valid := e.token(service.ScopeEntriesRead)

	rejected := map[string]string{
		"empty":            "",
		"bare token":       valid,
		"basic auth":       "Basic dXNlcjpwYXNz",
		"scheme only":      "Bearer",
		"scheme and space": "Bearer ",
		"wrong scheme":     "Token " + valid,
		"prefix only":      "Bearer stk_",
		"not a token":      "Bearer hunter2",
		"double bearer":    "Bearer Bearer " + valid,
	}

	for name, header := range rejected {
		t.Run(name, func(t *testing.T) {
			rec := e.do(call{Method: http.MethodGet, Path: "/api/v1/me",
				Headers: map[string]string{"Authorization": header}})
			requireProblem(t, rec, http.StatusUnauthorized)
		})
	}

	accepted := map[string]string{
		"canonical":  "Bearer " + valid,
		"lowercase":  "bearer " + valid,
		"mixed case": "BeArEr " + valid,
	}
	for name, header := range accepted {
		t.Run(name, func(t *testing.T) {
			rec := e.do(call{Method: http.MethodGet, Path: "/api/v1/me",
				Headers: map[string]string{"Authorization": header}})
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 — the Bearer scheme is case-insensitive (body: %s)",
					rec.Code, rec.Body.String())
			}
		})
	}
}

// TestV1RevokedTokenIsRejected: revocation must take effect on the API surface,
// not only in the management UI's list.
func TestV1RevokedTokenIsRejected(t *testing.T) {
	e := newV1Env(t)

	tok, raw, err := service.CreateAPIToken(e.Ctx, e.Pool, e.UserID, "to be revoked",
		[]string{service.ScopeEntriesRead}, nil)
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	if rec := e.get("/api/v1/me", raw); rec.Code != http.StatusOK {
		t.Fatalf("before revocation: status = %d (body: %s)", rec.Code, rec.Body.String())
	}

	revoked, err := service.RevokeAPIToken(e.Ctx, e.Pool, e.UserID, tok.ID)
	if err != nil || !revoked {
		t.Fatalf("revoking: revoked = %v, err = %v", revoked, err)
	}

	rec := e.get("/api/v1/me", raw)
	requireProblem(t, rec, http.StatusUnauthorized)
	if auth := rec.Header().Get("WWW-Authenticate"); !strings.Contains(auth, "invalid_token") {
		t.Errorf("WWW-Authenticate = %q, want it to carry error=\"invalid_token\"", auth)
	}
}

// TestV1ExpiredTokenIsRejected covers model.APIToken.Active through the
// middleware. The expiry is backdated directly because CreateAPIToken refuses
// to mint one already in the past.
func TestV1ExpiredTokenIsRejected(t *testing.T) {
	e := newV1Env(t)

	future := time.Now().Add(time.Hour)
	tok, raw, err := service.CreateAPIToken(e.Ctx, e.Pool, e.UserID, "expiring",
		[]string{service.ScopeEntriesRead}, &future)
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	if _, err := e.Pool.Exec(e.Ctx,
		`UPDATE api_tokens SET expires_at = NOW() - INTERVAL '1 minute' WHERE id = $1`, tok.ID); err != nil {
		t.Fatalf("backdating the expiry: %v", err)
	}

	requireProblem(t, e.get("/api/v1/me", raw), http.StatusUnauthorized)
}

// TestV1TokenOfADeletedUserIsRejected covers the fail-closed branch in
// RequireAPIToken: a token whose user cannot be loaded must 401, not 500.
func TestV1TokenOfADeletedUserIsRejected(t *testing.T) {
	e := newV1Env(t)

	doomedID, doomedEmail := e.seedUser("-doomed")
	raw := e.tokenFor(doomedID, service.ScopeEntriesRead)

	if rec := e.get("/api/v1/me", raw); rec.Code != http.StatusOK {
		t.Fatalf("before deletion: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	if _, err := e.Pool.Exec(e.Ctx, `DELETE FROM users WHERE email = $1`, doomedEmail); err != nil {
		t.Fatalf("deleting the user: %v", err)
	}

	// The FK cascade takes the token with the user, so this is the
	// unknown-token path; either way it must be a 401 and never a 500.
	rec := e.get("/api/v1/me", raw)
	requireProblem(t, rec, http.StatusUnauthorized)
}

// TestV1TokenUseIsRecorded checks the fire-and-forget last_used_at update
// actually lands. It is how a user answers "was this leaked token used?", so a
// silently failing goroutine would be worth knowing about.
func TestV1TokenUseIsRecorded(t *testing.T) {
	e := newV1Env(t)

	tok, raw, err := service.CreateAPIToken(e.Ctx, e.Pool, e.UserID, "touched",
		[]string{service.ScopeEntriesRead}, nil)
	if err != nil {
		t.Fatalf("minting: %v", err)
	}
	if rec := e.get("/api/v1/me", raw); rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}

	// The update is deliberately off the request path, so poll briefly rather
	// than assume it has landed.
	var lastUsed *time.Time
	for i := 0; i < 50; i++ {
		if err := e.Pool.QueryRow(e.Ctx,
			`SELECT last_used_at FROM api_tokens WHERE id = $1`, tok.ID).Scan(&lastUsed); err != nil {
			t.Fatalf("reading last_used_at: %v", err)
		}
		if lastUsed != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("last_used_at is still NULL a second after an authenticated request")
}

// TestV1ConcurrentIdempotentRetriesCreateOnce is the claim CLAUDE.md makes
// about INSERT ... ON CONFLICT DO NOTHING: "of two concurrent retries exactly
// one claims it and the other observes the claim — neither can execute twice."
// A check-then-insert would pass every sequential test in this package and fail
// this one.
func TestV1ConcurrentIdempotentRetriesCreateOnce(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	const n = 8
	c := call{Method: http.MethodPost, Path: "/api/v1/entries", Token: token,
		Body:    `{"date":"2026-08-05","calories":450,"name":"Concurrent"}`,
		Headers: idempotent("one-logical-operation")}

	statuses := make([]int, n)
	var wg sync.WaitGroup
	var start sync.WaitGroup
	start.Add(1)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start.Wait()
			statuses[i] = e.do(c).Code
		}(i)
	}
	start.Done()
	wg.Wait()

	for i, s := range statuses {
		if s >= 500 {
			t.Errorf("request %d returned %d; a concurrent retry must not be a server error", i, s)
		}
		// 201 (won the claim, or replayed it) and 409 (saw it in flight) are
		// both correct answers; anything else is not.
		if s != http.StatusCreated && s != http.StatusConflict {
			t.Errorf("request %d returned %d, want 201 or 409", i, s)
		}
	}

	var entries int
	if err := e.Pool.QueryRow(e.Ctx,
		`SELECT COUNT(*)::int FROM calorie_entries WHERE user_id = $1`, e.UserID).Scan(&entries); err != nil {
		t.Fatalf("counting entries: %v", err)
	}
	if entries != 1 {
		t.Fatalf("%d entries after %d concurrent retries with one key, want exactly 1 — "+
			"the claim is not atomic (statuses: %v)", entries, n, statuses)
	}
}
