package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"schautrack/internal/model"
	"schautrack/internal/service"
)

// withToken builds a request carrying an already-authenticated token, the way
// RequireAPIToken would leave it. This lets RequireScope be tested without a
// database — the scope decision is pure logic over the token's scope list.
func withToken(r *http.Request, scopes ...string) *http.Request {
	tok := &model.APIToken{ID: 1, UserID: 1, Name: "test", Prefix: "stk_abc123", Scopes: scopes}
	return r.WithContext(context.WithValue(r.Context(), apiTokenContextKey, tok))
}

func okHandler() (http.Handler, *bool) {
	called := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	return h, &called
}

func TestRequireScopeAllowsExactScope(t *testing.T) {
	next, called := okHandler()
	req := withToken(httptest.NewRequest(http.MethodGet, "/entries", nil), "entries:read")
	rec := httptest.NewRecorder()

	RequireScope(service.ScopeEntriesRead)(next).ServeHTTP(rec, req)

	if !*called {
		t.Error("handler was not called despite the token holding the scope")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestRequireScopeAllowsWriteForRead(t *testing.T) {
	next, called := okHandler()
	req := withToken(httptest.NewRequest(http.MethodGet, "/entries", nil), "entries:write")
	rec := httptest.NewRecorder()

	RequireScope(service.ScopeEntriesRead)(next).ServeHTTP(rec, req)

	if !*called {
		t.Error("entries:write should satisfy entries:read")
	}
}

func TestRequireScopeRejectsMissingScope(t *testing.T) {
	next, called := okHandler()
	req := withToken(httptest.NewRequest(http.MethodPost, "/entries", nil), "entries:read")
	rec := httptest.NewRecorder()

	RequireScope(service.ScopeEntriesWrite)(next).ServeHTTP(rec, req)

	if *called {
		t.Fatal("handler ran with an under-scoped token")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}

	// The 403 must name the missing scope; otherwise a user has to guess which
	// checkbox they forgot.
	var p map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if p["required_scope"] != service.ScopeEntriesWrite {
		t.Errorf("required_scope = %v, want %q", p["required_scope"], service.ScopeEntriesWrite)
	}
}

// TestRequireScopeFailsClosedWithoutToken checks the middleware does not treat
// a missing token as "no scope restriction". Mounting RequireScope without
// RequireAPIToken above it is a routing mistake; it must 401, not allow.
func TestRequireScopeFailsClosedWithoutToken(t *testing.T) {
	next, called := okHandler()
	req := httptest.NewRequest(http.MethodGet, "/entries", nil)
	rec := httptest.NewRecorder()

	RequireScope(service.ScopeEntriesRead)(next).ServeHTTP(rec, req)

	if *called {
		t.Fatal("handler ran with no token at all")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestGetAPITokenReturnsNilWhenAbsent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if tok := GetAPIToken(req); tok != nil {
		t.Errorf("GetAPIToken = %v, want nil on an unauthenticated request", tok)
	}
}

func TestGetAPITokenRoundTrips(t *testing.T) {
	req := withToken(httptest.NewRequest(http.MethodGet, "/", nil), "plan:read")
	tok := GetAPIToken(req)
	if tok == nil {
		t.Fatal("GetAPIToken = nil, want the token that was attached")
	}
	if len(tok.Scopes) != 1 || tok.Scopes[0] != "plan:read" {
		t.Errorf("scopes = %v, want [plan:read]", tok.Scopes)
	}
}

// TestAPITokenActive covers the expiry and revocation logic that decides
// whether a token still authenticates.
func TestAPITokenActive(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name  string
		token model.APIToken
		want  bool
	}{
		{"no expiry, not revoked", model.APIToken{}, true},
		{"expires in the future", model.APIToken{ExpiresAt: &future}, true},
		{"expired an hour ago", model.APIToken{ExpiresAt: &past}, false},
		{"expiring exactly now is expired", model.APIToken{ExpiresAt: &now}, false},
		{"revoked", model.APIToken{RevokedAt: &past}, false},
		{"revoked beats a valid expiry", model.APIToken{RevokedAt: &past, ExpiresAt: &future}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.Active(now); got != tt.want {
				t.Errorf("Active() = %v, want %v", got, tt.want)
			}
		})
	}
}
