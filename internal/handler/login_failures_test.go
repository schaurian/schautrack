package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"schautrack/internal/session"
)

func TestFailureTracker_CountsAndResets(t *testing.T) {
	ft := newFailureTracker(15*time.Minute, 100)

	if got := ft.Count("email:a@example.com"); got != 0 {
		t.Errorf("Count on empty tracker = %d, want 0", got)
	}

	ft.Record("email:a@example.com")
	ft.Record("email:a@example.com")
	ft.Record("email:a@example.com")
	if got := ft.Count("email:a@example.com"); got != 3 {
		t.Errorf("Count = %d, want 3", got)
	}
	// Other keys are unaffected
	if got := ft.Count("email:b@example.com"); got != 0 {
		t.Errorf("Count for other key = %d, want 0", got)
	}

	ft.Reset("email:a@example.com")
	if got := ft.Count("email:a@example.com"); got != 0 {
		t.Errorf("Count after Reset = %d, want 0", got)
	}
}

func TestFailureTracker_WindowExpiry(t *testing.T) {
	current := time.Now()
	ft := newFailureTracker(15*time.Minute, 100)
	ft.now = func() time.Time { return current }

	ft.Record("ip:203.0.113.9")
	ft.Record("ip:203.0.113.9")
	ft.Record("ip:203.0.113.9")
	if got := ft.Count("ip:203.0.113.9"); got != 3 {
		t.Fatalf("Count = %d, want 3", got)
	}

	// Advance past the window: the counter must expire.
	current = current.Add(16 * time.Minute)
	if got := ft.Count("ip:203.0.113.9"); got != 0 {
		t.Errorf("Count after window = %d, want 0", got)
	}

	// A new failure after expiry starts a fresh window at 1.
	ft.Record("ip:203.0.113.9")
	if got := ft.Count("ip:203.0.113.9"); got != 1 {
		t.Errorf("Count after expiry + record = %d, want 1", got)
	}
}

func TestFailureTracker_Bounded(t *testing.T) {
	current := time.Now()
	ft := newFailureTracker(15*time.Minute, 3)
	ft.now = func() time.Time { return current }

	ft.Record("k1")
	ft.Record("k2")
	ft.Record("k3")
	// At capacity with live entries: new keys must be dropped (fail open),
	// not grow the map unboundedly.
	ft.Record("k4")
	if got := ft.Count("k4"); got != 0 {
		t.Errorf("Count for key beyond capacity = %d, want 0 (dropped)", got)
	}
	// Existing keys still increment at capacity.
	ft.Record("k1")
	if got := ft.Count("k1"); got != 2 {
		t.Errorf("Count for existing key at capacity = %d, want 2", got)
	}

	// Once old entries expire, there is room for new keys again.
	current = current.Add(16 * time.Minute)
	ft.Record("k5")
	if got := ft.Count("k5"); got != 1 {
		t.Errorf("Count for new key after prune = %d, want 1", got)
	}
}

func TestLoginCaptchaRequired_ByEmailAndIP(t *testing.T) {
	orig := loginFailures
	loginFailures = newFailureTracker(15*time.Minute, 100)
	defer func() { loginFailures = orig }()

	sess := &session.Session{ID: "t", Data: make(map[string]any)}

	if loginCaptchaRequired(sess, "victim@example.com", "203.0.113.5") {
		t.Fatal("captcha required with zero failures")
	}

	// Server-side email counter alone triggers the captcha, regardless of
	// the (client-controlled) session counter.
	for i := 0; i < loginCaptchaThreshold; i++ {
		recordServerLoginFailure("victim@example.com", fmt.Sprintf("198.51.100.%d", i))
	}
	if !loginCaptchaRequired(sess, "victim@example.com", "203.0.113.5") {
		t.Error("captcha not required despite email failure count at threshold")
	}
	if loginCaptchaRequired(sess, "other@example.com", "203.0.113.5") {
		t.Error("captcha required for unrelated email/IP")
	}

	// IP counter alone triggers it too.
	for i := 0; i < loginCaptchaThreshold; i++ {
		recordServerLoginFailure(fmt.Sprintf("u%d@example.com", i), "203.0.113.77")
	}
	if !loginCaptchaRequired(sess, "other@example.com", "203.0.113.77") {
		t.Error("captcha not required despite IP failure count at threshold")
	}

	// Session counter still works as before.
	sess2 := &session.Session{ID: "t2", Data: make(map[string]any)}
	sess2.Set("loginFailedAttempts", loginCaptchaThreshold)
	if !loginCaptchaRequired(sess2, "fresh@example.com", "192.0.2.200") {
		t.Error("captcha not required despite session failure count at threshold")
	}

	// Successful login clears the server-side counters.
	clearLoginFailures(sess, "victim@example.com", "203.0.113.77")
	if loginCaptchaRequired(sess, "victim@example.com", "203.0.113.77") {
		t.Error("captcha still required after clearLoginFailures")
	}
}

// TestLogin_ServerSideCaptchaGate proves the captcha gate no longer depends on
// the client persisting its session cookie: a fresh session (attempts=0) with
// enough server-side failures for the email gets challenged before any DB
// access (Pool is nil — reaching the DB would panic).
func TestLogin_ServerSideCaptchaGate(t *testing.T) {
	orig := loginFailures
	loginFailures = newFailureTracker(15*time.Minute, 100)
	defer func() { loginFailures = orig }()

	for i := 0; i < loginCaptchaThreshold; i++ {
		recordServerLoginFailure("brute@example.com", fmt.Sprintf("198.51.100.%d", i))
	}

	h := &AuthHandler{Pool: nil} // nil pool: must not reach the DB
	body := `{"email":"Brute@Example.com","password":"whatever123"}`
	r := newRequestWithSession("POST", "/api/auth/login", body)
	w := httptest.NewRecorder()

	h.Login(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if req, _ := resp["requireCaptcha"].(bool); !req {
		t.Errorf("requireCaptcha = %v, want true; body = %s", resp["requireCaptcha"], w.Body.String())
	}
	if svg, _ := resp["captchaSvg"].(string); svg == "" {
		t.Error("expected a captchaSvg challenge in the response")
	}
}
