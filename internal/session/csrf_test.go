package session

import (
	"net/http/httptest"
	"testing"
)

func TestGenerateCsrfToken(t *testing.T) {
	sess := &Session{Data: map[string]any{}}

	token := GenerateCsrfToken(sess)
	if len(token) != 64 {
		t.Errorf("token length = %d, want 64", len(token))
	}

	// Should be stored in session
	if sess.GetString("csrfToken") != token {
		t.Error("token not stored in session")
	}

	// Should reuse existing token
	token2 := GenerateCsrfToken(sess)
	if token2 != token {
		t.Error("should reuse existing token")
	}
}

func TestValidateCsrfToken(t *testing.T) {
	token := "a" + "b" + "c" + "d"
	// Make a 64-char token
	for len(token) < 64 {
		token += "x"
	}
	token = token[:64]

	sess := &Session{Data: map[string]any{"csrfToken": token}}

	// Valid header
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("X-CSRF-Token", token)
	if !ValidateCsrfToken(r, sess) {
		t.Error("expected valid for matching token")
	}

	// Mismatched
	r2 := httptest.NewRequest("POST", "/", nil)
	r2.Header.Set("X-CSRF-Token", "b"+token[1:])
	if ValidateCsrfToken(r2, sess) {
		t.Error("expected invalid for mismatched token")
	}

	// Missing header
	r3 := httptest.NewRequest("POST", "/", nil)
	if ValidateCsrfToken(r3, sess) {
		t.Error("expected invalid for missing header")
	}

	// No session token
	sess2 := &Session{Data: map[string]any{}}
	r4 := httptest.NewRequest("POST", "/", nil)
	r4.Header.Set("X-CSRF-Token", token)
	if ValidateCsrfToken(r4, sess2) {
		t.Error("expected invalid for no session token")
	}
}
