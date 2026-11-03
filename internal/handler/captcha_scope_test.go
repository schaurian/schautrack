package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/service"
)

// Each auth flow must only require, and only accept, a captcha it issued
// itself. These drive the real handlers in sequence over one shared session —
// the way a browser tab moves between /register, /forgot-password and /login.

type captchaFlowEnv struct {
	ctx  context.Context
	pool *pgxpool.Pool
	h    *AuthHandler
	data map[string]any // the one session every request shares
}

func newCaptchaFlowEnv(t *testing.T) *captchaFlowEnv {
	t.Helper()
	ctx, pool := inviteTestPool(t)
	orig := loginFailures
	loginFailures = newFailureTracker(15*time.Minute, 100)
	t.Cleanup(func() { loginFailures = orig })
	// SMTP "configured" so forgot-password is reachable; nothing is sent to an
	// address with no account, and login never sends for a verified user.
	cfg := &config.Config{EnableRegistration: "open", SMTPHost: "smtp.invalid", SMTPFrom: "noreply@handler.test"}
	return &captchaFlowEnv{
		ctx: ctx, pool: pool,
		h: &AuthHandler{
			Pool: pool, Cfg: cfg,
			Settings: database.NewSettingsCache(pool),
			Email:    service.NewEmailService(cfg),
		},
		data: make(map[string]any),
	}
}

// seedLoginUser creates a verified user with 2FA on, so a correct password
// answers {"requireToken":true} without needing a session store.
func (e *captchaFlowEnv) seedLoginUser(t *testing.T, email, password string) {
	t.Helper()
	cleanup := func() { e.pool.Exec(e.ctx, `DELETE FROM users WHERE email = $1`, email) }
	cleanup()
	t.Cleanup(cleanup)
	hash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	if _, err := e.pool.Exec(e.ctx,
		`INSERT INTO users (email, password_hash, email_verified, totp_enabled) VALUES ($1, $2, true, true)`,
		email, hash); err != nil {
		t.Fatalf("seeding user: %v", err)
	}
}

func (e *captchaFlowEnv) call(t *testing.T, handler http.HandlerFunc, url string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	r, _ := newRequestWithSessionData(url, string(b), e.data)
	w := httptest.NewRecorder()
	handler(w, r)
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// solveCaptchaQuestion answers the non-visual "What is A plus B?" challenge
// a response carries, so the tests need no access to the session key.
func solveCaptchaQuestion(t *testing.T, resp map[string]any) string {
	t.Helper()
	q, _ := resp["captchaQuestion"].(string)
	if q == "" {
		q, _ = resp["question"].(string)
	}
	words := map[string]int{}
	for i, w := range []string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"} {
		words[w] = i
	}
	var a, b string
	if _, err := fmt.Sscanf(strings.TrimSuffix(q, "?"), "What is %s plus %s", &a, &b); err != nil {
		t.Fatalf("unparseable captcha question %q: %v", q, err)
	}
	return fmt.Sprint(words[a] + words[b])
}

// The reported bug: Continue on /register issues the registration captcha,
// the user abandons it and logs in with correct credentials. Login showed no
// captcha and must not demand or reject one.
func TestLogin_AbandonedRegistrationCaptchaDoesNotGateLogin(t *testing.T) {
	e := newCaptchaFlowEnv(t)
	const user, pw = "captcha-scope-login@handler.test", "longenoughpassword"
	e.seedLoginUser(t, user, pw)
	const registrant = "captcha-scope-abandoned@handler.test"
	e.pool.Exec(e.ctx, `DELETE FROM users WHERE email = $1`, registrant)

	code, resp := e.call(t, e.h.Register, "/api/auth/register", map[string]any{
		"step": "credentials", "email": registrant, "password": pw, "timezone": "UTC",
	})
	if code != http.StatusOK || resp["requireCaptcha"] != true {
		t.Fatalf("register credentials: status %d body %v, want the captcha step", code, resp)
	}

	code, resp = e.call(t, e.h.Login, "/api/auth/login", map[string]any{"email": user, "password": pw})
	if code != http.StatusOK || resp["requireToken"] != true {
		t.Fatalf("login after abandoned registration: status %d body %v, want 200 requireToken", code, resp)
	}
}

// Loading /forgot-password fetches GET /api/auth/captcha; going back to
// /login afterwards must not inherit that challenge either.
func TestLogin_ForgotPasswordCaptchaDoesNotGateLogin(t *testing.T) {
	e := newCaptchaFlowEnv(t)
	const user, pw = "captcha-scope-forgot@handler.test", "longenoughpassword"
	e.seedLoginUser(t, user, pw)

	if code, _ := e.call(t, e.h.Captcha, "/api/auth/captcha", nil); code != http.StatusOK {
		t.Fatalf("GET captcha: status %d", code)
	}
	code, resp := e.call(t, e.h.Login, "/api/auth/login", map[string]any{"email": user, "password": pw})
	if code != http.StatusOK || resp["requireToken"] != true {
		t.Fatalf("login after forgot-password captcha: status %d body %v, want 200 requireToken", code, resp)
	}
}

// triggerLoginCaptcha pushes the server-side failure counter for email over
// the threshold and lets Login issue its own challenge.
func (e *captchaFlowEnv) triggerLoginCaptcha(t *testing.T, email string) map[string]any {
	t.Helper()
	for i := 0; i < loginCaptchaThreshold; i++ {
		recordServerLoginFailure(email, fmt.Sprintf("198.51.100.%d", i))
	}
	code, resp := e.call(t, e.h.Login, "/api/auth/login", map[string]any{"email": email, "password": "whatever-wrong"})
	if code != http.StatusUnauthorized || resp["requireCaptcha"] != true {
		t.Fatalf("login gate: status %d body %v, want 401 requireCaptcha", code, resp)
	}
	return resp
}

// The answer to login's challenge must not complete registration.
func TestRegisterCaptcha_RejectsLoginChallengeAnswer(t *testing.T) {
	e := newCaptchaFlowEnv(t)
	const registrant = "captcha-scope-register@handler.test"
	cleanup := func() { e.pool.Exec(e.ctx, `DELETE FROM users WHERE email = $1`, registrant) }
	cleanup()
	t.Cleanup(cleanup)

	code, resp := e.call(t, e.h.Register, "/api/auth/register", map[string]any{
		"step": "credentials", "email": registrant, "password": "longenoughpassword", "timezone": "UTC",
	})
	if code != http.StatusOK || resp["requireCaptcha"] != true {
		t.Fatalf("register credentials: status %d body %v", code, resp)
	}
	registerAnswer := solveCaptchaQuestion(t, resp)
	const victim = "captcha-scope-victim@handler.test"
	loginAnswer := solveCaptchaQuestion(t, e.triggerLoginCaptcha(t, victim))
	// The arithmetic answers are small sums and can coincide; re-roll login's
	// challenge (a wrong answer issues a fresh one) until they differ, so an
	// accept below can only mean the flows share state.
	for loginAnswer == registerAnswer {
		_, r := e.call(t, e.h.Login, "/api/auth/login", map[string]any{"email": victim, "password": "x", "captcha": "wrong"})
		loginAnswer = solveCaptchaQuestion(t, r)
	}

	code, resp = e.call(t, e.h.Register, "/api/auth/register", map[string]any{
		"step": "captcha", "captcha": loginAnswer,
	})
	if code != http.StatusBadRequest || resp["error"] != "Invalid captcha." {
		t.Fatalf("register with login's captcha answer: status %d body %v, want 400 Invalid captcha.", code, resp)
	}
	var exists bool
	e.pool.QueryRow(e.ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)`, registrant).Scan(&exists)
	if exists {
		t.Fatal("an account was created with another flow's captcha answer")
	}
}

// The answer to login's challenge must not unlock forgot-password, and
// forgot-password's own challenge (GET /api/auth/captcha) still works.
func TestForgotPassword_RejectsLoginChallengeAnswer(t *testing.T) {
	e := newCaptchaFlowEnv(t)
	loginResp := e.triggerLoginCaptcha(t, "captcha-scope-reset@handler.test")

	code, resp := e.call(t, e.h.ForgotPassword, "/api/auth/forgot-password", map[string]any{
		"email": "captcha-scope-nobody@handler.test", "captcha": solveCaptchaQuestion(t, loginResp),
	})
	if code != http.StatusBadRequest || resp["error"] != "Invalid captcha." {
		t.Fatalf("forgot-password with login's captcha answer: status %d body %v, want 400 Invalid captcha.", code, resp)
	}

	_, own := e.call(t, e.h.Captcha, "/api/auth/captcha", nil)
	code, resp = e.call(t, e.h.ForgotPassword, "/api/auth/forgot-password", map[string]any{
		"email": "captcha-scope-nobody@handler.test", "captcha": solveCaptchaQuestion(t, own),
	})
	if code != http.StatusOK {
		t.Fatalf("forgot-password with its own captcha: status %d body %v, want 200", code, resp)
	}
}

// A captcha login legitimately issued (brute-force gate) is still enforced:
// a wrong answer is rejected, and fetching another flow's challenge in
// between neither clears nor replaces it.
func TestLogin_OwnCaptchaStillEnforced(t *testing.T) {
	e := newCaptchaFlowEnv(t)
	const user, pw = "captcha-scope-brute@handler.test", "longenoughpassword"
	e.seedLoginUser(t, user, pw)
	e.triggerLoginCaptcha(t, user)
	e.call(t, e.h.Captcha, "/api/auth/captcha", nil) // another flow's challenge

	code, resp := e.call(t, e.h.Login, "/api/auth/login", map[string]any{"email": user, "password": pw})
	if code != http.StatusBadRequest || resp["error"] != "Invalid captcha." {
		t.Fatalf("login without solving its captcha: status %d body %v, want 400 Invalid captcha.", code, resp)
	}
	code, resp = e.call(t, e.h.Login, "/api/auth/login", map[string]any{
		"email": user, "password": pw, "captcha": solveCaptchaQuestion(t, resp),
	})
	if code != http.StatusOK || resp["requireToken"] != true {
		t.Fatalf("login with its own captcha solved: status %d body %v, want 200 requireToken", code, resp)
	}
}
