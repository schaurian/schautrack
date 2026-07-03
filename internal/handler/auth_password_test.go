package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"schautrack/internal/session"
)

// newRequestWithSessionData builds a POST request whose context carries the
// given session, and returns both the request and the session so the test can
// inspect counter state after the handler runs.
func newRequestWithSessionData(url, body string, data map[string]any) (*http.Request, *session.Session) {
	r := httptest.NewRequest("POST", url, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	sess := &session.Session{
		ID:     "test-session-id",
		Data:   data,
		MaxAge: session.AnonMaxAge,
	}
	ctx := session.WithTestSession(r.Context(), sess)
	return r.WithContext(ctx), sess
}

// TestResetPassword_LockoutRejectsValidCode proves the per-session attempt
// counter locks the reset flow after 5 failed attempts: once resetAttempts is
// at the cap, even a would-be-valid code is rejected with 429 *before* any DB
// lookup (a nil pool would panic if the guard did not short-circuit first).
func TestResetPassword_LockoutRejectsValidCode(t *testing.T) {
	h := &AuthHandler{Pool: nil} // nil pool: any DB access after the guard would panic

	body := `{"code":"123456","password":"","confirm_password":""}`
	r, sess := newRequestWithSessionData("/api/auth/reset-password", body, map[string]any{
		"resetEmail":        "victim@example.com",
		"resetCodeVerified": false,
		"resetAttempts":     5,
	})
	w := httptest.NewRecorder()

	h.ResetPassword(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusTooManyRequests)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "Too many attempts") {
		t.Errorf("error = %q, want message about too many attempts", msg)
	}
	// The guard returns before incrementing, so the counter stays at the cap.
	if attempts, _ := sess.GetInt("resetAttempts"); attempts != 5 {
		t.Errorf("resetAttempts = %d, want 5", attempts)
	}
}

// TestResetPassword_UnderLimitNotLocked proves the threshold is exactly 5:
// at 4 recorded attempts the flow is NOT locked and proceeds past the guard to
// normal validation (here, an empty code -> 400 "Code is required.").
func TestResetPassword_UnderLimitNotLocked(t *testing.T) {
	h := &AuthHandler{Pool: nil}

	body := `{"code":"","password":"","confirm_password":""}`
	r, _ := newRequestWithSessionData("/api/auth/reset-password", body, map[string]any{
		"resetEmail":        "user@example.com",
		"resetCodeVerified": false,
		"resetAttempts":     4,
	})
	w := httptest.NewRecorder()

	h.ResetPassword(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (not locked out)", w.Code, http.StatusBadRequest)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "Code is required") {
		t.Errorf("error = %q, want message about code required", msg)
	}
}

// TestResetPassword_NoSession rejects requests without an active reset session.
func TestResetPassword_NoSession(t *testing.T) {
	h := &AuthHandler{Pool: nil}

	body := `{"code":"123456"}`
	r, _ := newRequestWithSessionData("/api/auth/reset-password", body, map[string]any{})
	w := httptest.NewRecorder()

	h.ResetPassword(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "No reset session") {
		t.Errorf("error = %q, want message about no reset session", msg)
	}
}
