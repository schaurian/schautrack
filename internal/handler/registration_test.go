package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"schautrack/internal/config"
	"schautrack/internal/database"
)

func TestRegistrationMode(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"empty is open", "", regModeOpen},
		{"open is open", "open", regModeOpen},
		{"true is open", "true", regModeOpen},
		{"invite is invite", "invite", regModeInvite},
		{"false is closed", "false", regModeClosed},
		{"unknown value falls back to open", "yes", regModeOpen},
		{"uppercase invite is invite", "INVITE", regModeInvite},
		{"padded false is closed", "  false  ", regModeClosed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := registrationMode(tt.value); got != tt.want {
				t.Errorf("registrationMode(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// invite/closed mode both reject at the credentials step before any DB access,
// so we can drive them with a nil pool. The settings cache resolves the mode
// from the env-backed config value (GetEffectiveSetting short-circuits on a
// non-empty env value without touching the pool).

func TestRegisterCredentials_InviteMode_RejectsWithoutCode(t *testing.T) {
	h := &AuthHandler{
		Pool:     nil, // must not be touched — rejection happens before any query
		Cfg:      &config.Config{EnableRegistration: "invite"},
		Settings: database.NewSettingsCache(nil),
	}

	body := `{"step":"credentials","email":"test@example.com","password":"longenoughpassword","timezone":"UTC"}`
	r := newRequestWithSession("POST", "/api/auth/register", body)
	w := httptest.NewRecorder()

	h.Register(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if req, _ := resp["requireInviteCode"].(bool); !req {
		t.Errorf("expected requireInviteCode=true in response, got %v", resp)
	}
}

func TestRegisterCredentials_ClosedMode_RejectsRegistration(t *testing.T) {
	h := &AuthHandler{
		Pool:     nil,
		Cfg:      &config.Config{EnableRegistration: "false"},
		Settings: database.NewSettingsCache(nil),
	}

	// Even with an invite code supplied, closed mode must reject entirely.
	body := `{"step":"credentials","email":"test@example.com","password":"longenoughpassword","timezone":"UTC","invite_code":"anything"}`
	r := newRequestWithSession("POST", "/api/auth/register", body)
	w := httptest.NewRecorder()

	h.Register(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if req, _ := resp["requireInviteCode"].(bool); req {
		t.Errorf("closed mode must not offer an invite path, got %v", resp)
	}
}
