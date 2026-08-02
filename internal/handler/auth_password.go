package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"schautrack/internal/service"
	"schautrack/internal/session"
)

var errResetTokenNoLongerValid = errors.New("password reset token is no longer valid")

type resetTokenExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// consumePasswordResetToken revalidates and consumes the token at the moment
// the password is changed. Code verification and password submission are two
// separate requests, so the token may expire or be consumed by another reset
// between them.
func consumePasswordResetToken(ctx context.Context, tx resetTokenExecutor, tokenID, userID int) error {
	tag, err := tx.Exec(ctx, `
		UPDATE password_reset_tokens
		SET used = TRUE
		WHERE id = $1 AND user_id = $2 AND used = FALSE AND expires_at > NOW()`,
		tokenID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errResetTokenNoLongerValid
	}
	return nil
}

// ForgotPassword handles POST /api/auth/forgot-password
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email   string `json:"email"`
		Captcha string `json:"captcha"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	if !h.Email.IsConfigured() {
		ErrorJSON(w, http.StatusBadRequest, "Password recovery not available.")
		return
	}

	sess := session.GetSession(r)
	captchaAnswer := sess.GetString("captchaAnswer")
	if !service.VerifyCaptcha(captchaAnswer, body.Captcha) {
		c := service.GenerateCaptcha()
		sess.Set("captchaAnswer", c.Text)
		JSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid captcha.", "captchaSvg": c.Data, "captchaQuestion": c.Question})
		return
	}

	email := strings.ToLower(strings.TrimSpace(body.Email))
	if email == "" {
		ErrorJSON(w, http.StatusBadRequest, "Email is required.")
		return
	}

	var userID int
	var userEmail string
	var userLanguage *string
	err := h.Pool.QueryRow(r.Context(), "SELECT id, email, language FROM users WHERE email = $1", email).Scan(&userID, &userEmail, &userLanguage)
	if err == nil {
		// Delete old unused tokens
		if _, err := h.Pool.Exec(r.Context(), "DELETE FROM password_reset_tokens WHERE user_id = $1 AND used = FALSE", userID); err != nil {
			slog.Error("failed to delete old password reset tokens", "error", err)
		}
		code := service.GenerateResetCode()
		if _, err := h.Pool.Exec(r.Context(),
			"INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
			userID, code, time.Now().Add(30*time.Minute)); err != nil {
			slog.Error("failed to insert password reset token", "error", err)
		} else if err := h.Email.SendPasswordResetEmail(userEmail, code, derefLang(userLanguage)); err != nil {
			// Deliberately NOT surfaced to the client: this endpoint must
			// stay non-enumerating, and a send-failure response would reveal
			// that the account exists. Log it and return the generic success.
			slog.Error("failed to send password reset email", "error", err)
		}
	}
	// Always return success (don't reveal if email exists)
	sess.Delete("captchaAnswer")
	sess.Set("resetEmail", email)
	sess.Set("resetCodeVerified", false)
	OkJSON(w)
}

// ResetPassword handles POST /api/auth/reset-password
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code            string `json:"code"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	sess := session.GetSession(r)
	email := sess.GetString("resetEmail")
	if email == "" {
		ErrorJSON(w, http.StatusBadRequest, "No reset session.")
		return
	}

	codeVerified := false
	if v, ok := sess.Data["resetCodeVerified"]; ok {
		codeVerified, _ = v.(bool)
	}

	if !codeVerified {
		attempts, _ := sess.GetInt("resetAttempts")
		if attempts >= 5 {
			ErrorJSON(w, http.StatusTooManyRequests, "Too many attempts.")
			return
		}
		if body.Code == "" {
			ErrorJSON(w, http.StatusBadRequest, "Code is required.")
			return
		}
		// Verify code
		var tokenID, userID int
		var expiresAt time.Time
		err := h.Pool.QueryRow(r.Context(), `
			SELECT prt.id, prt.user_id, prt.expires_at
			FROM password_reset_tokens prt
			JOIN users u ON u.id = prt.user_id
			WHERE u.email = $1 AND prt.token = $2 AND prt.used = FALSE
			ORDER BY prt.created_at DESC LIMIT 1`,
			email, body.Code).Scan(&tokenID, &userID, &expiresAt)
		if err != nil || time.Now().After(expiresAt) {
			sess.Set("resetAttempts", attempts+1)
			ErrorJSON(w, http.StatusBadRequest, "Invalid or expired code.")
			return
		}
		sess.Set("resetCodeVerified", true)
		sess.Delete("resetAttempts")
		sess.Set("resetTokenId", tokenID)
		sess.Set("resetUserId", userID)
		JSON(w, http.StatusOK, map[string]any{"ok": true, "codeVerified": true})
		return
	}

	// Set new password
	if body.Password == "" {
		ErrorJSON(w, http.StatusBadRequest, "Password is required.")
		return
	}
	if body.Password != body.ConfirmPassword {
		ErrorJSON(w, http.StatusBadRequest, "Passwords do not match.")
		return
	}
	if len(body.Password) < 10 {
		ErrorJSON(w, http.StatusBadRequest, "Password must be at least 10 characters.")
		return
	}

	userID, _ := sess.GetInt("resetUserId")
	tokenID, _ := sess.GetInt("resetTokenId")
	if userID == 0 || tokenID == 0 {
		sess.Delete("resetEmail")
		ErrorJSON(w, http.StatusBadRequest, "Session expired.")
		return
	}

	hash, err := hashPassword(body.Password)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not reset password.")
		return
	}

	// Revalidate and consume the token, update the password, and invalidate every
	// existing session atomically: an attacker holding a stolen session
	// cookie must not keep access after the victim resets their password.
	// The caller's own (anonymous) session carries no userId and survives.
	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not reset password.")
		return
	}
	defer tx.Rollback(r.Context())
	if err := consumePasswordResetToken(r.Context(), tx, tokenID, userID); err != nil {
		if errors.Is(err, errResetTokenNoLongerValid) {
			sess.Delete("resetEmail")
			sess.Delete("resetCodeVerified")
			sess.Delete("resetTokenId")
			sess.Delete("resetUserId")
			ErrorJSON(w, http.StatusBadRequest, "Reset code expired or already used. Please start again.")
			return
		}
		ErrorJSON(w, http.StatusInternalServerError, "Could not reset password.")
		return
	}
	if _, err := tx.Exec(r.Context(), "UPDATE users SET password_hash = $1 WHERE id = $2", hash, userID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not reset password.")
		return
	}
	if err := invalidateUserSessions(r.Context(), tx, userID, ""); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not reset password.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not reset password.")
		return
	}

	sess.Delete("resetEmail")
	sess.Delete("resetCodeVerified")
	sess.Delete("resetTokenId")
	sess.Delete("resetUserId")
	sess.Delete("resetAttempts")
	OkJSON(w)
}
