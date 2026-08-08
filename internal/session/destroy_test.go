package session

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDestroyLeavesTheSessionUsableWhenTheDeleteFails documents the behaviour
// that makes checking Destroy's error mandatory rather than tidy.
//
// Destroy returns early when the DELETE fails: the clearing cookie is never
// written and sess.destroyed is never set. So a caller that discards the error
// — which POST /api/auth/logout did — answers "ok" to a logout that removed
// nothing and cleared nothing. The user is told they are signed out and is
// not, which on a shared machine is the entire point of the button.
//
// This test pins the shape of the failure so the handler-side fix cannot be
// reverted as unnecessary.
func TestDestroyLeavesTheSessionUsableWhenTheDeleteFails(t *testing.T) {
	wantErr := errors.New("connection reset by peer")
	db := &fakeDB{execErr: wantErr}
	s := &Store{pool: db}

	sess := &Session{ID: "sid-under-test", Data: map[string]any{"userId": 1}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)

	err := s.Destroy(rec, req, sess)

	if err == nil {
		t.Fatal("Destroy returned nil on a failing DELETE; the caller has no way to know the " +
			"session survived")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Destroy error = %v, want it to wrap %v", err, wantErr)
	}

	// The two things that make an ignored error dangerous rather than untidy.
	if got := rec.Result().Cookies(); len(got) != 0 {
		t.Errorf("a clearing cookie was written despite the failed DELETE: %v — the client would "+
			"believe it was signed out", got)
	}
	if sess.destroyed {
		t.Error("session marked destroyed despite the failed DELETE; the deferred-save writer " +
			"would then skip re-persisting it and the state would be inconsistent")
	}
}

// The success path must still do both halves, so the assertions above are
// about the failure and not about Destroy having quietly stopped working.
func TestDestroyClearsTheCookieWhenTheDeleteSucceeds(t *testing.T) {
	db := &fakeDB{}
	s := &Store{pool: db}

	sess := &Session{ID: "sid-under-test", Data: map[string]any{"userId": 1}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)

	if err := s.Destroy(rec, req, sess); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if !sess.destroyed {
		t.Error("session not marked destroyed after a successful DELETE")
	}

	var cleared *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName {
			cleared = c
		}
	}
	if cleared == nil {
		t.Fatalf("no %s cookie was written; the browser would keep the old one", CookieName)
	}
	if cleared.MaxAge >= 0 || cleared.Value != "" {
		t.Errorf("cookie = %+v, want an empty value and a negative MaxAge to expire it", cleared)
	}
}
