package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"schautrack/internal/session"
)

// newRequestWithSession creates a request with a session in its context,
// so handlers that call session.GetSession(r) get a valid session.
// It uses the session middleware with a test handler to inject the session properly.
func newRequestWithSession(method, url string, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, url, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, url, nil)
	}
	ctx := session.WithTestSession(r.Context(), &session.Session{
		ID:     "test-session-id",
		Data:   make(map[string]any),
		MaxAge: session.AnonMaxAge,
	})
	return r.WithContext(ctx)
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	// Hash a known password, then verify with a wrong one
	hash, err := hashPassword("correctpassword")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}

	valid, err := verifyPassword(hash, "wrongpassword")
	if err != nil {
		t.Fatalf("verifyPassword error: %v", err)
	}
	if valid {
		t.Error("verifyPassword returned true for wrong password")
	}
}

func TestVerifyPassword_CorrectPassword(t *testing.T) {
	hash, err := hashPassword("correctpassword")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}

	valid, err := verifyPassword(hash, "correctpassword")
	if err != nil {
		t.Fatalf("verifyPassword error: %v", err)
	}
	if !valid {
		t.Error("verifyPassword returned false for correct password")
	}
}

func TestVerifyPassword_EmptyInputs(t *testing.T) {
	valid, _ := verifyPassword("", "password")
	if valid {
		t.Error("empty hash should return false")
	}

	valid, _ = verifyPassword("somehash", "")
	if valid {
		t.Error("empty password should return false")
	}
}

func TestRegisterCredentials_ShortPassword(t *testing.T) {
	// The registerCredentials function validates password length >= 10.
	// We can't call it directly without a pool, but we can test the
	// validation logic by calling the Register handler with a mock that
	// will fail at the password check before hitting the DB.
	h := &AuthHandler{Pool: nil} // nil pool - should fail before DB access

	body := `{"step":"credentials","email":"test@example.com","password":"short","timezone":"UTC"}`
	r := newRequestWithSession("POST", "/api/auth/register", body)
	w := httptest.NewRecorder()

	h.Register(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "10 characters") {
		t.Errorf("error = %q, want message about 10 characters", msg)
	}
}

func TestRegisterCredentials_EmptyEmail(t *testing.T) {
	h := &AuthHandler{Pool: nil}

	body := `{"step":"credentials","email":"","password":"longenoughpassword","timezone":"UTC"}`
	r := newRequestWithSession("POST", "/api/auth/register", body)
	w := httptest.NewRecorder()

	h.Register(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "required") {
		t.Errorf("error = %q, want message about required fields", msg)
	}
}

func TestRegisterCredentials_InvalidStep(t *testing.T) {
	h := &AuthHandler{Pool: nil}

	body := `{"step":"invalid","email":"test@example.com","password":"longenoughpassword"}`
	r := newRequestWithSession("POST", "/api/auth/register", body)
	w := httptest.NewRecorder()

	h.Register(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestLogin_EmptyCredentials(t *testing.T) {
	h := &AuthHandler{Pool: nil}

	body := `{"email":"","password":""}`
	r := newRequestWithSession("POST", "/api/auth/login", body)
	w := httptest.NewRecorder()

	h.Login(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "required") {
		t.Errorf("error = %q, want message about required fields", msg)
	}
}

func TestLogin_InvalidJSON(t *testing.T) {
	h := &AuthHandler{Pool: nil}

	r := newRequestWithSession("POST", "/api/auth/login", "not json")
	w := httptest.NewRecorder()

	h.Login(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCsrfToken_ReturnsToken(t *testing.T) {
	r := newRequestWithSession("GET", "/api/csrf", "")
	w := httptest.NewRecorder()

	CsrfToken(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	token, ok := resp["token"].(string)
	if !ok || token == "" {
		t.Error("expected non-empty token in response")
	}
	if len(token) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("token length = %d, want 64", len(token))
	}
}

func TestCsrfToken_SameTokenOnRepeatedCalls(t *testing.T) {
	r := newRequestWithSession("GET", "/api/csrf", "")
	w1 := httptest.NewRecorder()
	CsrfToken(w1, r)

	var resp1 map[string]any
	json.Unmarshal(w1.Body.Bytes(), &resp1)
	token1 := resp1["token"].(string)

	// Call again with the same session (same request context)
	w2 := httptest.NewRecorder()
	CsrfToken(w2, r)

	var resp2 map[string]any
	json.Unmarshal(w2.Body.Bytes(), &resp2)
	token2 := resp2["token"].(string)

	if token1 != token2 {
		t.Errorf("tokens differ across calls: %q vs %q", token1, token2)
	}
}

func TestRecordLoginFailure(t *testing.T) {
	sess := &session.Session{
		ID:   "test",
		Data: make(map[string]any),
	}

	recordLoginFailure(sess)
	attempts, _ := sess.GetInt("loginFailedAttempts")
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}

	recordLoginFailure(sess)
	attempts, _ = sess.GetInt("loginFailedAttempts")
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2", attempts)
	}
}
