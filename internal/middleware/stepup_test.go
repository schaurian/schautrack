package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"schautrack/internal/session"
)

func TestStepUpResponse(t *testing.T) {
	tests := []struct {
		name           string
		hasPassword    bool
		passkeyCount   int
		totpEnabled    bool
		wantMethods    []string
		wantTotpReq    bool
	}{
		{"password only", true, 0, false, []string{"password"}, false},
		{"password + totp", true, 0, true, []string{"password"}, true},
		{"passkey only", false, 2, false, []string{"passkey"}, false},
		{"passkey + totp (totp ignored without password)", false, 1, true, []string{"passkey"}, false},
		{"both", true, 1, false, []string{"password", "passkey"}, false},
		{"none — locked out", false, 0, false, []string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stepUpResponse(tt.hasPassword, tt.passkeyCount, tt.totpEnabled)
			if !reflect.DeepEqual(got["methods"], tt.wantMethods) {
				t.Errorf("methods = %v, want %v", got["methods"], tt.wantMethods)
			}
			if got["totpRequired"] != tt.wantTotpReq {
				t.Errorf("totpRequired = %v, want %v", got["totpRequired"], tt.wantTotpReq)
			}
			if got["error"] != "step_up_required" || got["requireStepUp"] != true {
				t.Errorf("missing error/requireStepUp markers: %v", got)
			}
		})
	}
}

// Middleware short-circuits when the session has fresh step-up.
func TestRequireStepUp_PassesThroughWhenRecent(t *testing.T) {
	sess := &session.Session{Data: map[string]any{
		"step_up_at": int(time.Now().Unix()),
	}}
	if !sess.HasRecentStepUp() {
		t.Fatal("test setup: session should be considered recent")
	}

	called := false
	mw := RequireStepUp(nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("POST", "/sensitive", nil)
	r = r.WithContext(session.WithTestSession(r.Context(), sess))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if !called {
		t.Error("downstream handler was not called")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// Middleware blocks (and returns structured 403) when no session at all.
// We can't exercise the user-state branches here without a DB, but we can
// verify the no-user / no-step-up path produces the expected envelope.
func TestRequireStepUp_BlocksWithoutStepUp_NoUser(t *testing.T) {
	sess := &session.Session{Data: map[string]any{}}

	called := false
	mw := RequireStepUp(nil)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	r := httptest.NewRequest("POST", "/sensitive", nil)
	r = r.WithContext(session.WithTestSession(r.Context(), sess))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	if called {
		t.Error("downstream should not have been called")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["error"] != "step_up_required" {
		t.Errorf("error = %v, want step_up_required", body["error"])
	}
	if body["requireStepUp"] != true {
		t.Errorf("requireStepUp = %v, want true", body["requireStepUp"])
	}
}
