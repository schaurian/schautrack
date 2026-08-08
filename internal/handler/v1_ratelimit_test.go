package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/service"
)

// The AI-estimate and barcode routes reuse the app's own handlers. For a long
// time they did not reuse the limiters mounted in front of those handlers, so
// /api/v1 was the cheap path to the two most expensive things the server does:
// 60 estimates a minute per token against 5 per 5 minutes for a logged-in
// browser (issue #292). These tests are what stops that from coming back.

// stubAuth stands in for middleware.RequireAPIToken, which needs a database CI
// does not have. It injects exactly what the real middleware injects on
// success, so everything below it — scope checks, limiters, handlers — runs
// unchanged.
func stubAuth(tokenID, userID int, scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := middleware.WithTestUser(r.Context(), &model.User{ID: userID, Email: "t@example.com"})
			ctx = middleware.WithTestAPIToken(ctx, &model.APIToken{
				ID: tokenID, UserID: userID, Scopes: scopes,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// countingHandler answers like the app's own handler and records how often it
// actually ran. The count is the real assertion: a 429 produced *after* the
// provider was called would cost the same money as a 200.
func countingHandler(calls *int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		*calls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}
}

// checkProblem429 asserts the rejection is RFC 9457, not the legacy envelope.
// Invariant #3: every /api/v1 response, including the ones written before a
// handler runs, is problem+json.
func checkProblem429(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("%s: status = %d, want 429", what, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("%s: Content-Type = %q, want application/problem+json", what, ct)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Errorf("%s: no Retry-After header on a 429", what)
	}
	var p map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("%s: body is not JSON: %v", what, err)
	}
	for _, field := range []string{"type", "title", "status"} {
		if _, ok := p[field]; !ok {
			t.Errorf("%s: problem detail has no %q field: %s", what, field, rec.Body.String())
		}
	}
	if _, legacy := p["ok"]; legacy {
		t.Errorf(`%s: 429 carries the legacy {"ok": false} envelope: %s`, what, rec.Body.String())
	}
}

func v1Do(t *testing.T, router chi.Router, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "203.0.113.5:44444"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestV1AIEstimateIsRateLimited — the estimate route must stop at its own
// ceiling, and must stop *before* reaching the handler that spends money.
func TestV1AIEstimateIsRateLimited(t *testing.T) {
	var calls int
	h := &V1Handler{
		AIEstimate: countingHandler(&calls, `{"ok":true,"calories":420}`),
		Auth:       stubAuth(1, 7, service.ScopeAIEstimate),
		AILimiter:  middleware.NewUserRateLimiter(2, time.Minute, false),
		// The generic per-token limiter stays mounted: the operation limiter
		// composes with it rather than replacing it.
		TokenLimiter: middleware.NewTokenRateLimiter(100, time.Minute, false),
	}
	router := h.MountAPIV1(nil)

	for i := range 2 {
		if rec := v1Do(t, router, http.MethodPost, "/ai/estimate"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (body %s)", i+1, rec.Code, rec.Body.String())
		}
	}

	checkProblem429(t, v1Do(t, router, http.MethodPost, "/ai/estimate"), "third estimate")
	if calls != 2 {
		t.Errorf("AI handler ran %d times, want 2 — the limiter must reject before the provider is called", calls)
	}
}

// TestV1AIEstimateLimitIsPerAccount closes the obvious escape hatch: tokens are
// free to mint (up to service.MaxTokensPerUser), so a per-token budget would be
// twenty budgets for anyone who wanted them.
func TestV1AIEstimateLimitIsPerAccount(t *testing.T) {
	var calls int
	limiter := middleware.NewUserRateLimiter(1, time.Minute, false)
	estimate := countingHandler(&calls, `{"ok":true,"calories":420}`)

	first := (&V1Handler{AIEstimate: estimate, AILimiter: limiter,
		Auth: stubAuth(1, 7, service.ScopeAIEstimate)}).MountAPIV1(nil)
	// Same account, different token — as if the caller minted a fresh one after
	// running out of budget.
	second := (&V1Handler{AIEstimate: estimate, AILimiter: limiter,
		Auth: stubAuth(2, 7, service.ScopeAIEstimate)}).MountAPIV1(nil)

	if rec := v1Do(t, first, http.MethodPost, "/ai/estimate"); rec.Code != http.StatusOK {
		t.Fatalf("first token: status = %d, want 200", rec.Code)
	}
	checkProblem429(t, v1Do(t, second, http.MethodPost, "/ai/estimate"), "second token of the same account")
	if calls != 1 {
		t.Errorf("AI handler ran %d times, want 1", calls)
	}
}

// TestV1BarcodeIsRateLimited — same argument, cheaper operation: the lookup
// hits a third-party database that the app itself calls at most 30 times a
// minute.
func TestV1BarcodeIsRateLimited(t *testing.T) {
	var calls int
	h := &V1Handler{
		Barcode:        countingHandler(&calls, `{"ok":true,"product":{"name":"Oats"}}`),
		Auth:           stubAuth(1, 7, service.ScopeFoodsRead),
		BarcodeLimiter: middleware.NewUserRateLimiter(2, time.Minute, false),
		TokenLimiter:   middleware.NewTokenRateLimiter(100, time.Minute, false),
	}
	router := h.MountAPIV1(nil)

	for i := range 2 {
		if rec := v1Do(t, router, http.MethodGet, "/barcode/4006381333931"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (body %s)", i+1, rec.Code, rec.Body.String())
		}
	}

	checkProblem429(t, v1Do(t, router, http.MethodGet, "/barcode/4006381333931"), "third lookup")
	if calls != 2 {
		t.Errorf("barcode handler ran %d times, want 2 — the limiter must reject before the upstream call", calls)
	}
}

// TestV1OperationLimitersAreIndependent — the two limiters are sized to
// different operations, so exhausting one must not close the other, and neither
// may leak onto the rest of the surface.
func TestV1OperationLimitersAreIndependent(t *testing.T) {
	var aiCalls, barcodeCalls int
	h := &V1Handler{
		AIEstimate:     countingHandler(&aiCalls, `{"ok":true,"calories":420}`),
		Barcode:        countingHandler(&barcodeCalls, `{"ok":true,"product":{"name":"Oats"}}`),
		Auth:           stubAuth(1, 7, service.ScopeAIEstimate, service.ScopeFoodsRead),
		AILimiter:      middleware.NewUserRateLimiter(1, time.Minute, false),
		BarcodeLimiter: middleware.NewUserRateLimiter(1, time.Minute, false),
	}
	router := h.MountAPIV1(nil)

	if rec := v1Do(t, router, http.MethodPost, "/ai/estimate"); rec.Code != http.StatusOK {
		t.Fatalf("first estimate: status = %d, want 200", rec.Code)
	}
	checkProblem429(t, v1Do(t, router, http.MethodPost, "/ai/estimate"), "second estimate")

	if rec := v1Do(t, router, http.MethodGet, "/barcode/4006381333931"); rec.Code != http.StatusOK {
		t.Errorf("barcode after the AI budget ran out: status = %d, want 200 — the limiters share a bucket", rec.Code)
	}
	if barcodeCalls != 1 {
		t.Errorf("barcode handler ran %d times, want 1", barcodeCalls)
	}
}

// TestV1OperationLimitersRunAfterScopeCheck — a 403 costs nothing to serve, so
// it must not spend the account's estimate budget. Otherwise a wrongly-scoped
// token could deny service to the correctly-scoped one beside it.
func TestV1OperationLimitersRunAfterScopeCheck(t *testing.T) {
	var calls int
	limiter := middleware.NewUserRateLimiter(1, time.Minute, false)
	estimate := countingHandler(&calls, `{"ok":true,"calories":420}`)

	unscoped := (&V1Handler{AIEstimate: estimate, AILimiter: limiter,
		Auth: stubAuth(1, 7, service.ScopeEntriesRead)}).MountAPIV1(nil)
	scoped := (&V1Handler{AIEstimate: estimate, AILimiter: limiter,
		Auth: stubAuth(2, 7, service.ScopeAIEstimate)}).MountAPIV1(nil)

	if rec := v1Do(t, unscoped, http.MethodPost, "/ai/estimate"); rec.Code != http.StatusForbidden {
		t.Fatalf("token without ai:estimate: status = %d, want 403", rec.Code)
	}
	if rec := v1Do(t, scoped, http.MethodPost, "/ai/estimate"); rec.Code != http.StatusOK {
		t.Errorf("scoped token after a rejected one: status = %d, want 200 — a 403 consumed the budget", rec.Code)
	}
	if calls != 1 {
		t.Errorf("AI handler ran %d times, want 1", calls)
	}
}

// TestV1AuthDefaultsToTokenAuth — Auth is nil in production wiring, and nil
// must mean "require a bearer token", never "no authentication".
func TestV1AuthDefaultsToTokenAuth(t *testing.T) {
	router := (&V1Handler{}).MountAPIV1(nil)
	if rec := v1Do(t, router, http.MethodGet, "/me"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — a nil V1Handler.Auth must not leave /api/v1 open", rec.Code)
	}
}
