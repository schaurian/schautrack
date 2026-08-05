package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"schautrack/internal/model"
)

func okNext() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

// reqWithToken builds a request already carrying an authenticated token, as
// RequireAPIToken would leave it.
func reqWithToken(id int, ip string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil)
	r.RemoteAddr = ip + ":12345"
	tok := &model.APIToken{ID: id, UserID: id, Scopes: []string{"entries:read"}}
	return r.WithContext(context.WithValue(r.Context(), apiTokenContextKey, tok))
}

// TestTokenRateLimiterBucketsByToken is the whole point of the per-token
// limiter: two tokens sharing one IP must not share a budget. Per-IP bucketing
// means everyone behind a CGNAT throttles each other.
func TestTokenRateLimiterBucketsByToken(t *testing.T) {
	rl := NewTokenRateLimiter(2, time.Minute, false)
	h := rl.Middleware(okNext())

	// Token 1 exhausts its own allowance from a shared address.
	for i := range 2 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, reqWithToken(1, "203.0.113.9"))
		if w.Code != http.StatusOK {
			t.Fatalf("token 1 request %d: status = %d, want 200", i+1, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithToken(1, "203.0.113.9"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("token 1 over limit: status = %d, want 429", w.Code)
	}

	// Token 2, same IP, must be unaffected.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, reqWithToken(2, "203.0.113.9"))
	if w.Code != http.StatusOK {
		t.Errorf("token 2 from the same IP: status = %d, want 200 — buckets are not per-token", w.Code)
	}
}

// TestTokenRateLimiterFallsBackToIP checks the limiter is safe if it is ever
// mounted above authentication: with no token it must still throttle, not let
// everything through on one shared empty key.
func TestTokenRateLimiterFallsBackToIP(t *testing.T) {
	rl := NewTokenRateLimiter(1, time.Minute, false)
	h := rl.Middleware(okNext())

	first := httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil)
	first.RemoteAddr = "198.51.100.4:1111"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, first)
	if w.Code != http.StatusOK {
		t.Fatalf("first anonymous request: status = %d, want 200", w.Code)
	}

	second := httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil)
	second.RemoteAddr = "198.51.100.4:2222"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, second)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("second anonymous request from the same IP: status = %d, want 429", w.Code)
	}

	// A different address keeps its own budget.
	other := httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil)
	other.RemoteAddr = "198.51.100.5:3333"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, other)
	if w.Code != http.StatusOK {
		t.Errorf("different IP: status = %d, want 200", w.Code)
	}
}

// TestRateLimitSetsRetryAfter checks a 429 tells the client when to come back.
// Without it every client is left to invent its own backoff, and the polite
// ones guess too long while the rest hammer.
func TestRateLimitSetsRetryAfter(t *testing.T) {
	rl := NewProblemRateLimiter(1, time.Minute, false)
	h := rl.Middleware(okNext())

	r := httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil)
	r.RemoteAddr = "192.0.2.7:5555"
	h.ServeHTTP(httptest.NewRecorder(), r)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}

	ra := w.Header().Get("Retry-After")
	if ra == "" {
		t.Fatal("no Retry-After header on a 429")
	}
	secs, err := strconv.Atoi(ra)
	if err != nil {
		t.Fatalf("Retry-After = %q, want an integer number of seconds", ra)
	}
	// Never 0: "retry immediately" is advice guaranteed to fail again.
	if secs < 1 || secs > 60 {
		t.Errorf("Retry-After = %d, want between 1 and 60 for a one-minute window", secs)
	}

	var p map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if p["status"] != float64(http.StatusTooManyRequests) {
		t.Errorf("problem status = %v, want 429", p["status"])
	}
}

// The legacy limiter keeps its {"error": ...} body, but should still carry
// Retry-After — it costs nothing and helps the SPA behave.
func TestLegacyRateLimitAlsoSetsRetryAfter(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute, false)
	h := rl.Middleware(okNext())

	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	r.RemoteAddr = "192.0.2.8:6666"
	h.ServeHTTP(httptest.NewRecorder(), r)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After on the legacy limiter's 429")
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json — the legacy shape must not change", ct)
	}
}

func TestRetryAfterSecondsNeverZero(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want int
	}{
		{-time.Second, 1},
		{0, 1},
		{time.Millisecond, 1},
		{time.Second, 1},
		{1500 * time.Millisecond, 2}, // rounds up, never down
		{30 * time.Second, 30},
		{time.Minute, 60},
	}
	for _, tt := range tests {
		if got := retryAfterSeconds(tt.in); got != tt.want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
