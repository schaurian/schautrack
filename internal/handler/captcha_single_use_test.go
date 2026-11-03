package handler

import (
	"fmt"
	"net/http"
	"testing"
)

// A solved captcha is consumed: replaying the same answer must not pass the
// same flow's gate a second time. Builds on captchaFlowEnv
// (captcha_scope_test.go).

func TestLoginCaptcha_SolvedAnswerCannotBeReplayed(t *testing.T) {
	e := newCaptchaFlowEnv(t)
	const user, pw = "captcha-once-login@handler.test", "longenoughpassword"
	e.seedLoginUser(t, user, pw)

	answer := solveCaptchaQuestion(t, e.triggerLoginCaptcha(t, user))
	code, resp := e.call(t, e.h.Login, "/api/auth/login", map[string]any{"email": user, "password": pw, "captcha": answer})
	if code != http.StatusOK || resp["requireToken"] != true {
		t.Fatalf("first use of the solved captcha: status %d body %v, want 200 requireToken", code, resp)
	}

	// The account comes under attack again from elsewhere, so login demands a
	// captcha once more. The answer already spent must not satisfy it.
	for i := 0; i < loginCaptchaThreshold; i++ {
		recordServerLoginFailure(user, fmt.Sprintf("198.51.100.%d", 50+i))
	}
	code, resp = e.call(t, e.h.Login, "/api/auth/login", map[string]any{"email": user, "password": pw, "captcha": answer})
	if code == http.StatusOK || resp["requireCaptcha"] != true {
		t.Fatalf("replayed login captcha: status %d body %v, want a fresh challenge, not a login", code, resp)
	}
}

func TestRegisterCaptcha_SolvedAnswerCannotBeReplayed(t *testing.T) {
	e := newCaptchaFlowEnv(t)
	const registrant = "captcha-once-register@handler.test"
	cleanup := func() { e.pool.Exec(e.ctx, `DELETE FROM users WHERE email = $1`, registrant) }
	cleanup()
	t.Cleanup(cleanup)

	code, resp := e.call(t, e.h.Register, "/api/auth/register", map[string]any{
		"step": "credentials", "email": registrant, "password": "longenoughpassword", "timezone": "UTC",
	})
	if code != http.StatusOK || resp["requireCaptcha"] != true {
		t.Fatalf("register credentials: status %d body %v", code, resp)
	}
	answer := solveCaptchaQuestion(t, resp)
	pending := e.data["pendingRegistration"]

	// Spend the answer on an attempt that gets past the captcha but fails
	// later (the address was taken in between) — the captcha is still used up.
	if _, err := e.pool.Exec(e.ctx, `INSERT INTO users (email, password_hash) VALUES ($1, 'x')`, registrant); err != nil {
		t.Fatalf("seeding the conflicting account: %v", err)
	}
	code, resp = e.call(t, e.h.Register, "/api/auth/register", map[string]any{"step": "captcha", "captcha": answer})
	if code != http.StatusConflict {
		t.Fatalf("first use of the solved captcha: status %d body %v, want 409 (captcha accepted, address taken)", code, resp)
	}

	// Even with a pending registration back in place, the spent answer must
	// not get through the captcha step again.
	cleanup()
	e.data["pendingRegistration"] = pending
	code, resp = e.call(t, e.h.Register, "/api/auth/register", map[string]any{"step": "captcha", "captcha": answer})
	if code != http.StatusBadRequest || resp["error"] != "Invalid captcha." {
		t.Fatalf("replayed register captcha: status %d body %v, want 400 Invalid captcha.", code, resp)
	}
}

func TestForgotPasswordCaptcha_SolvedAnswerCannotBeReplayed(t *testing.T) {
	e := newCaptchaFlowEnv(t)
	_, own := e.call(t, e.h.Captcha, "/api/auth/captcha", nil)
	answer := solveCaptchaQuestion(t, own)
	body := map[string]any{"email": "captcha-once-nobody@handler.test", "captcha": answer}

	if code, resp := e.call(t, e.h.ForgotPassword, "/api/auth/forgot-password", body); code != http.StatusOK {
		t.Fatalf("first use of the solved captcha: status %d body %v, want 200", code, resp)
	}
	code, resp := e.call(t, e.h.ForgotPassword, "/api/auth/forgot-password", body)
	if code != http.StatusBadRequest || resp["error"] != "Invalid captcha." {
		t.Fatalf("replayed forgot-password captcha: status %d body %v, want 400 Invalid captcha.", code, resp)
	}
}

// Wrong passwords in one session reach the threshold and the "Invalid
// credentials." reply itself carries the next challenge
// (replyWithCaptchaIfNeeded). It must land under login's key only, solving it
// must log in, and the register / forgot-password challenges in flight in the
// same session must be left exactly as they were.
func TestLogin_WrongPasswordCaptchaIsScopedToLogin(t *testing.T) {
	e := newCaptchaFlowEnv(t)
	const user, pw = "captcha-once-wrongpw@handler.test", "longenoughpassword"
	e.seedLoginUser(t, user, pw)
	const registrant = "captcha-once-wrongpw-reg@handler.test"
	e.pool.Exec(e.ctx, `DELETE FROM users WHERE email = $1`, registrant)

	if code, resp := e.call(t, e.h.Register, "/api/auth/register", map[string]any{
		"step": "credentials", "email": registrant, "password": pw, "timezone": "UTC",
	}); code != http.StatusOK {
		t.Fatalf("register credentials: status %d body %v", code, resp)
	}
	e.call(t, e.h.Captcha, "/api/auth/captcha", nil)
	regBefore, resetBefore := e.data[registerCaptchaKey], e.data[resetCaptchaKey]
	if regBefore == nil || resetBefore == nil {
		t.Fatalf("setup: register/reset challenges not in the session: %v", e.data)
	}

	var resp map[string]any
	var code int
	for i := 1; i <= loginCaptchaThreshold; i++ {
		code, resp = e.call(t, e.h.Login, "/api/auth/login", map[string]any{"email": user, "password": "wrong-password-x"})
		if code != http.StatusUnauthorized || resp["error"] != "Invalid credentials." {
			t.Fatalf("wrong password #%d: status %d body %v, want 401 Invalid credentials.", i, code, resp)
		}
	}
	if resp["requireCaptcha"] != true {
		t.Fatalf("after %d wrong passwords the reply carries no captcha: %v", loginCaptchaThreshold, resp)
	}
	if e.data[loginCaptchaKey] == nil {
		t.Fatal("the challenge was not stored under the login key")
	}
	if e.data[registerCaptchaKey] != regBefore || e.data[resetCaptchaKey] != resetBefore {
		t.Fatal("issuing the login captcha changed the register or forgot-password challenge")
	}

	code, resp = e.call(t, e.h.Login, "/api/auth/login", map[string]any{
		"email": user, "password": pw, "captcha": solveCaptchaQuestion(t, resp),
	})
	if code != http.StatusOK || resp["requireToken"] != true {
		t.Fatalf("login with the issued captcha solved: status %d body %v, want 200 requireToken", code, resp)
	}
}
