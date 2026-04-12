package handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"

	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/session"
)

// VerifyEmail handles POST /api/auth/verify-email
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	sess := session.GetSession(r)
	email := sess.GetString("verifyEmail")
	if email == "" {
		ErrorJSON(w, http.StatusBadRequest, "No verification session.")
		return
	}

	attempts, _ := sess.GetInt("verifyAttempts")
	if attempts >= 5 {
		ErrorJSON(w, http.StatusTooManyRequests, "Too many attempts.")
		return
	}

	code := strings.TrimSpace(body.Code)
	if code == "" {
		ErrorJSON(w, http.StatusBadRequest, "Code is required.")
		return
	}

	tx, txErr := h.Pool.Begin(r.Context())
	if txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not verify email.")
		return
	}
	defer tx.Rollback(r.Context())

	// Atomically find and mark the token as used to prevent TOCTOU races.
	var userID int
	err := tx.QueryRow(r.Context(), `
		UPDATE email_verification_tokens evt
		SET used = TRUE
		FROM users u
		WHERE u.id = evt.user_id
			AND u.email = $1
			AND evt.token = $2
			AND evt.used = FALSE
			AND evt.expires_at > NOW()
		RETURNING evt.user_id`,
		email, code).Scan(&userID)

	if err != nil {
		sess.Set("verifyAttempts", attempts+1)
		ErrorJSON(w, http.StatusBadRequest, "Invalid or expired code.")
		return
	}

	if _, txErr = tx.Exec(r.Context(), "UPDATE users SET email_verified = TRUE WHERE id = $1", userID); txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not verify email.")
		return
	}
	if txErr = tx.Commit(r.Context()); txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not verify email.")
		return
	}

	sess.Delete("verifyEmail")
	sess.Delete("verifyAttempts")
	sess.SetUserID(userID)
	OkJSON(w)
}

// VerifyEmailResend handles POST /api/auth/verify-email/resend
func (h *AuthHandler) VerifyEmailResend(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Captcha string `json:"captcha"`
	}
	ReadJSON(r, &body)

	sess := session.GetSession(r)
	email := sess.GetString("verifyEmail")
	if email == "" {
		ErrorJSON(w, http.StatusBadRequest, "No verification session.")
		return
	}

	resendAttempts, _ := sess.GetInt("resendAttempts")
	if resendAttempts >= 3 {
		ErrorJSON(w, http.StatusTooManyRequests, "Too many resend requests.")
		return
	}

	if resendAttempts > 0 {
		lastResendAt, _ := sess.Data["lastResendAt"].(float64)
		elapsed := time.Since(time.Unix(int64(lastResendAt), 0))
		if elapsed < 5*time.Minute {
			remaining := int((5*time.Minute - elapsed).Seconds())
			JSON(w, http.StatusTooManyRequests, map[string]any{
				"ok": false, "error": fmt.Sprintf("Please wait %ds.", remaining),
				"cooldown": remaining,
			})
			return
		}
		captchaAnswer := sess.GetString("resendCaptchaAnswer")
		if !service.VerifyCaptcha(captchaAnswer, body.Captcha) {
			c := service.GenerateCaptcha()
			sess.Set("resendCaptchaAnswer", c.Text)
			JSON(w, http.StatusBadRequest, map[string]any{
				"ok": false, "error": "Invalid captcha.", "captchaSvg": c.Data, "requireCaptcha": true,
			})
			return
		}
		sess.Delete("resendCaptchaAnswer")
	}

	var userID int
	var emailVerified bool
	err := h.Pool.QueryRow(r.Context(), "SELECT id, email_verified FROM users WHERE email = $1", email).Scan(&userID, &emailVerified)
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "User not found.")
		return
	}
	if emailVerified {
		OkJSON(w, map[string]any{"alreadyVerified": true})
		return
	}

	code := service.GenerateResetCode()
	if _, err := h.Pool.Exec(r.Context(),
		"INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
		userID, code, time.Now().Add(30*time.Minute)); err != nil {
		slog.Error("failed to insert verification token during resend", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Could not send verification email.")
		return
	}
	h.Email.SendVerificationEmail(email, code)

	sess.Set("resendAttempts", resendAttempts+1)
	sess.Set("verifyAttempts", 0)
	sess.Set("lastResendAt", float64(time.Now().Unix()))

	if resendAttempts == 0 {
		c := service.GenerateCaptcha()
		sess.Set("resendCaptchaAnswer", c.Text)
		JSON(w, http.StatusOK, map[string]any{"ok": true, "nextRequiresCaptcha": true, "captchaSvg": c.Data})
		return
	}
	OkJSON(w)
}

// EmailChangeRequest handles POST /settings/email/request
func (h *AuthHandler) EmailChangeRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		NewEmail string `json:"new_email"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)
	newEmail := strings.ToLower(strings.TrimSpace(body.NewEmail))

	if newEmail == "" || !strings.Contains(newEmail, "@") {
		ErrorJSON(w, http.StatusBadRequest, "Please enter a valid email address.")
		return
	}
	if newEmail == strings.ToLower(user.Email) {
		ErrorJSON(w, http.StatusBadRequest, "New email is the same as your current email.")
		return
	}

	var exists bool
	if err := h.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = $1)", newEmail).Scan(&exists); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not check email availability.")
		return
	}
	if exists {
		ErrorJSON(w, http.StatusConflict, "This email address is already in use.")
		return
	}

	var passwordHash string
	var totpEnabled bool
	var totpSecret *string
	err := h.Pool.QueryRow(r.Context(),
		"SELECT password_hash, totp_enabled, totp_secret FROM users WHERE id = $1",
		user.ID).Scan(&passwordHash, &totpEnabled, &totpSecret)
	if err != nil {
		ErrorJSON(w, http.StatusNotFound, "User not found.")
		return
	}

	valid, _ := verifyPassword(passwordHash, body.Password)
	if !valid {
		ErrorJSON(w, http.StatusUnauthorized, "Incorrect password.")
		return
	}

	if totpEnabled {
		if body.TOTPCode == "" {
			ErrorJSON(w, http.StatusBadRequest, "Please enter your 2FA code.")
			return
		}
		if totpSecret == nil || !totp.Validate(body.TOTPCode, *totpSecret) {
			ErrorJSON(w, http.StatusUnauthorized, "Invalid 2FA code.")
			return
		}
	}

	code := service.GenerateResetCode()
	if _, err := h.Pool.Exec(r.Context(),
		"INSERT INTO email_verification_tokens (user_id, token, expires_at, new_email) VALUES ($1, $2, $3, $4)",
		user.ID, code, time.Now().Add(30*time.Minute), newEmail); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not initiate email change.")
		return
	}
	h.Email.SendEmailChangeVerification(newEmail, code)

	sess := session.GetSession(r)
	sess.Set("pendingEmailChange", newEmail)
	sess.Set("pendingEmailChangeCreatedAt", float64(time.Now().Unix()))
	sess.Set("emailChangeAttempts", 0)
	OkJSON(w)
}

// EmailChangeVerify handles POST /settings/email/verify
func (h *AuthHandler) EmailChangeVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	sess := session.GetSession(r)
	user := middleware.GetCurrentUser(r)
	pendingEmail := sess.GetString("pendingEmailChange")

	createdAt, _ := sess.Data["pendingEmailChangeCreatedAt"].(float64)
	if pendingEmail == "" || (createdAt > 0 && time.Since(time.Unix(int64(createdAt), 0)) > 30*time.Minute) {
		sess.Delete("pendingEmailChange")
		sess.Delete("pendingEmailChangeCreatedAt")
		sess.Delete("emailChangeAttempts")
		ErrorJSON(w, http.StatusBadRequest, "Email change request expired. Please start again.")
		return
	}

	code := strings.TrimSpace(body.Code)
	if code == "" {
		ErrorJSON(w, http.StatusBadRequest, "Please enter the verification code.")
		return
	}

	attempts, _ := sess.GetInt("emailChangeAttempts")
	sess.Set("emailChangeAttempts", attempts+1)
	if attempts+1 > 5 {
		sess.Delete("pendingEmailChange")
		sess.Delete("emailChangeAttempts")
		ErrorJSON(w, http.StatusTooManyRequests, "Too many failed attempts. Please start over.")
		return
	}

	tx, txErr := h.Pool.Begin(r.Context())
	if txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not change email.")
		return
	}
	defer tx.Rollback(r.Context())

	// Atomically find and mark the token as used to prevent TOCTOU races.
	var newEmail string
	err := tx.QueryRow(r.Context(), `
		UPDATE email_verification_tokens
		SET used = TRUE
		WHERE user_id = $1 AND token = $2 AND used = FALSE
			AND new_email IS NOT NULL AND expires_at > NOW()
		RETURNING new_email`,
		user.ID, code).Scan(&newEmail)

	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid or expired verification code.")
		return
	}

	if _, txErr = tx.Exec(r.Context(), "UPDATE users SET email = $1 WHERE id = $2", newEmail, user.ID); txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not change email.")
		return
	}
	if txErr = tx.Commit(r.Context()); txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not change email.")
		return
	}

	sess.Delete("pendingEmailChange")
	sess.Delete("pendingEmailChangeCreatedAt")
	sess.Delete("emailChangeAttempts")
	OkJSON(w)
}

// EmailChangeCancel handles POST /settings/email/cancel
func (h *AuthHandler) EmailChangeCancel(w http.ResponseWriter, r *http.Request) {
	sess := session.GetSession(r)
	sess.Delete("pendingEmailChange")
	sess.Delete("pendingEmailChangeCreatedAt")
	sess.Delete("emailChangeAttempts")
	OkJSON(w)
}

// DeleteAccount handles POST /delete
func (h *AuthHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)
	if user == nil {
		ErrorJSON(w, http.StatusUnauthorized, "Session invalid. Please log in again.")
		return
	}

	var passwordHash string
	var totpEnabled bool
	var totpSecret *string
	err := h.Pool.QueryRow(r.Context(),
		"SELECT password_hash, totp_enabled, totp_secret FROM users WHERE id = $1",
		user.ID).Scan(&passwordHash, &totpEnabled, &totpSecret)
	if err != nil {
		ErrorJSON(w, http.StatusNotFound, "Account not found. Please log in again.")
		return
	}

	valid, _ := verifyPassword(passwordHash, body.Password)
	if !valid {
		ErrorJSON(w, http.StatusUnauthorized, "Incorrect password.")
		return
	}

	if totpEnabled {
		if body.Token == "" {
			ErrorJSON(w, http.StatusBadRequest, "Enter your 2FA code to confirm deletion.")
			return
		}
		verified := totpSecret != nil && totp.Validate(body.Token, *totpSecret)
		if !verified {
			verified = verifyAndUseBackupCodeForLogin(r, h.Pool, user.ID, body.Token)
		}
		if !verified {
			ErrorJSON(w, http.StatusUnauthorized, "Invalid 2FA code.")
			return
		}
	}

	// Delete user in transaction
	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not delete account. Please try again.")
		return
	}
	defer tx.Rollback(r.Context())

	tables := []string{
		"DELETE FROM totp_backup_codes WHERE user_id = $1",
		"DELETE FROM daily_notes WHERE user_id = $1",
		"DELETE FROM calorie_entries WHERE user_id = $1",
		"DELETE FROM weight_entries WHERE user_id = $1",
		"DELETE FROM ai_usage WHERE user_id = $1",
		"DELETE FROM account_links WHERE requester_id = $1 OR target_id = $1",
		"DELETE FROM password_reset_tokens WHERE user_id = $1",
		"DELETE FROM email_verification_tokens WHERE user_id = $1",
		"DELETE FROM users WHERE id = $1",
	}
	for _, q := range tables {
		if _, err := tx.Exec(r.Context(), q, user.ID); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not delete account. Please try again.")
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not delete account. Please try again.")
		return
	}

	sess := session.GetSession(r)
	h.SessionStore.Destroy(w, r, sess)
	OkJSON(w)
}
