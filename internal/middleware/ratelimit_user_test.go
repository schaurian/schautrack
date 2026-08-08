package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"schautrack/internal/model"
)

// reqWithUserToken builds a request carrying an authenticated token for a given
// account, as RequireAPIToken would leave it.
func reqWithUserToken(tokenID, userID int, ip string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/ai/estimate", nil)
	r.RemoteAddr = ip + ":12345"
	tok := &model.APIToken{ID: tokenID, UserID: userID, Scopes: []string{"ai:estimate"}}
	return r.WithContext(context.WithValue(r.Context(), apiTokenContextKey, tok))
}

// TestUserRateLimiterBucketsByAccount is the whole point of the per-user
// limiter: the budget for an expensive operation must belong to the account,
// not to the token. A user may hold MaxTokensPerUser (20) tokens and can mint a
// fresh one on demand, so a per-token bucket on something that spends the
// operator's money is a bucket that refills whenever the caller feels like it.
func TestUserRateLimiterBucketsByAccount(t *testing.T) {
	rl := NewUserRateLimiter(2, time.Minute, false)
	h := rl.Middleware(okNext())

	// User 7 spends its allowance through token 1.
	for i := range 2 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, reqWithUserToken(1, 7, "203.0.113.9"))
		if w.Code != http.StatusOK {
			t.Fatalf("token 1 request %d: status = %d, want 200", i+1, w.Code)
		}
	}

	// A *different token of the same user* must find the bucket empty.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUserToken(2, 7, "203.0.113.9"))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("second token of the same account: status = %d, want 429 — minting another token must not refill the budget", w.Code)
	}

	// A different account is unaffected, even from the same address.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUserToken(3, 8, "203.0.113.9"))
	if w.Code != http.StatusOK {
		t.Errorf("other account from the same IP: status = %d, want 200 — buckets are not per-account", w.Code)
	}
}

// TestUserRateLimiterFallsBackToIP keeps the limiter safe if it is ever mounted
// above authentication: with no token it must still throttle rather than let
// everything through on one shared empty key.
func TestUserRateLimiterFallsBackToIP(t *testing.T) {
	rl := NewUserRateLimiter(1, time.Minute, false)
	h := rl.Middleware(okNext())

	anon := func(ip string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/ai/estimate", nil)
		r.RemoteAddr = ip + ":1111"
		return r
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, anon("198.51.100.4"))
	if w.Code != http.StatusOK {
		t.Fatalf("first anonymous request: status = %d, want 200", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, anon("198.51.100.4"))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("second anonymous request from the same IP: status = %d, want 429", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, anon("198.51.100.5"))
	if w.Code != http.StatusOK {
		t.Errorf("different IP: status = %d, want 200", w.Code)
	}
}

// TestUserRateLimiterRejectsWithProblemJSON — these limiters guard /api/v1
// routes, where every error is RFC 9457. A 429 in the legacy {"error": ...}
// shape would be the one response a client cannot parse like the rest.
func TestUserRateLimiterRejectsWithProblemJSON(t *testing.T) {
	rl := NewUserRateLimiter(1, time.Minute, false)
	h := rl.Middleware(okNext())

	h.ServeHTTP(httptest.NewRecorder(), reqWithUserToken(1, 42, "192.0.2.7"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUserToken(1, 42, "192.0.2.7"))

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Error("no Retry-After header on a 429")
	}
	var p map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if _, ok := p["type"]; !ok {
		t.Errorf("problem has no type field: %s", w.Body.String())
	}
	if _, legacy := p["ok"]; legacy {
		t.Errorf(`429 carries the legacy {"ok": false} envelope: %s`, w.Body.String())
	}
}
