package handler

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/session"
)

// AuthHandler holds dependencies for auth routes.
type AuthHandler struct {
	Pool         *pgxpool.Pool
	SessionStore *session.Store
	Email        *service.EmailService
	Cfg          *config.Config
	Settings     *database.SettingsCache
}

// Login handles POST /api/auth/login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Token    string `json:"token"`
		Captcha  string `json:"captcha"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	sess := session.GetSession(r)

	// TOTP step
	if body.Token != "" {
		pendingUserID, ok := sess.GetInt("pendingUserId")
		if !ok {
			ErrorJSON(w, http.StatusBadRequest, "Invalid 2FA session.")
			return
		}
		user, err := middleware.GetUserByID(r.Context(), h.Pool, pendingUserID)
		if err != nil || !user.TOTPEnabled || user.TOTPSecret == nil {
			sess.Delete("pendingUserId")
			ErrorJSON(w, http.StatusBadRequest, "Invalid 2FA session.")
			return
		}
		verified := totp.Validate(body.Token, *user.TOTPSecret)
		if !verified {
			// Try as backup code
			verified = verifyAndUseBackupCodeForLogin(r, h.Pool, user.ID, body.Token)
		}
		if !verified {
			ErrorJSON(w, http.StatusUnauthorized, "Invalid 2FA code.")
			return
		}
		newSess, err := h.SessionStore.Regenerate(r, sess)
		if err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Session error.")
			return
		}
		newSess.SetUserID(user.ID)
		session.SetSession(r, newSess)
		OkJSON(w)
		return
	}

	if body.Email == "" || body.Password == "" {
		ErrorJSON(w, http.StatusBadRequest, "Email and password are required.")
		return
	}

	// Check captcha if too many failed attempts
	failedAttempts, _ := sess.GetInt("loginFailedAttempts")
	if failedAttempts >= 3 {
		captchaAnswer := sess.GetString("captchaAnswer")
		if !service.VerifyCaptcha(captchaAnswer, body.Captcha) {
			c := service.GenerateCaptcha()
			sess.Set("captchaAnswer", c.Text)
			JSON(w, http.StatusBadRequest, map[string]any{
				"ok": false, "error": "Invalid captcha.",
				"captchaSvg": c.Data, "requireCaptcha": true,
			})
			return
		}
		sess.Delete("captchaAnswer")
	}

	// Look up user
	var userID int
	var passwordHash string
	var totpEnabled bool
	var totpSecret *string
	var emailVerified bool
	var email string
	err := h.Pool.QueryRow(r.Context(),
		"SELECT id, email, password_hash, totp_enabled, totp_secret, email_verified FROM users WHERE email = $1",
		strings.ToLower(strings.TrimSpace(body.Email)),
	).Scan(&userID, &email, &passwordHash, &totpEnabled, &totpSecret, &emailVerified)

	if err != nil {
		recordLoginFailure(sess)
		replyWithCaptchaIfNeeded(w, sess)
		return
	}

	valid, err := verifyPassword(passwordHash, body.Password)
	if err != nil || !valid {
		recordLoginFailure(sess)
		replyWithCaptchaIfNeeded(w, sess)
		return
	}

	// Migrate bcrypt -> argon2 if needed
	if strings.HasPrefix(passwordHash, "$2b$") || strings.HasPrefix(passwordHash, "$2a$") {
		go migratePasswordHash(h.Pool, userID, body.Password)
	}

	if h.Email.IsConfigured() && !emailVerified {
		sess.Set("verifyEmail", email)
		JSON(w, http.StatusOK, map[string]any{"ok": false, "requireVerification": true})
		return
	}

	if totpEnabled {
		sess.Set("pendingUserId", userID)
		JSON(w, http.StatusOK, map[string]any{"ok": false, "requireToken": true})
		return
	}

	newSess, err := h.SessionStore.Regenerate(r, sess)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Session error.")
		return
	}
	newSess.SetUserID(userID)
	session.SetSession(r, newSess)
	OkJSON(w)
}

// Register handles POST /api/auth/register
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Step       string `json:"step"`
		Email      string `json:"email"`
		Password   string `json:"password"`
		Timezone   string `json:"timezone"`
		Captcha    string `json:"captcha"`
		InviteCode string `json:"invite_code"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	sess := session.GetSession(r)

	switch body.Step {
	case "credentials":
		h.registerCredentials(w, r, sess, body.Email, body.Password, body.Timezone, body.InviteCode)
	case "captcha":
		h.registerCaptcha(w, r, sess, body.Captcha)
	default:
		ErrorJSON(w, http.StatusBadRequest, "Invalid step.")
	}
}

func (h *AuthHandler) getRegistrationMode(r *http.Request) string {
	result := h.Settings.GetEffectiveSetting(r.Context(), "registration_mode", h.Cfg.RegistrationMode)
	if result.Value != nil && *result.Value == "invite" {
		return "invite"
	}
	return "open"
}

func (h *AuthHandler) registerCredentials(w http.ResponseWriter, r *http.Request, sess *session.Session, email, password, timezone, inviteCode string) {
	emailClean := strings.ToLower(strings.TrimSpace(email))
	if emailClean == "" || password == "" {
		ErrorJSON(w, http.StatusBadRequest, "Email and password are required.")
		return
	}
	if len(password) < 10 {
		ErrorJSON(w, http.StatusBadRequest, "Password must be at least 10 characters.")
		return
	}

	// Check registration mode
	if h.getRegistrationMode(r) == "invite" {
		inviteCode = strings.TrimSpace(inviteCode)
		if inviteCode == "" {
			JSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "Registration requires an invite code.", "requireInviteCode": true})
			return
		}
		// Validate invite code
		var inviteID int
		var inviteEmail *string
		var usedBy *int
		var expiresAt *time.Time
		err := h.Pool.QueryRow(r.Context(),
			"SELECT id, email, used_by, expires_at FROM invite_codes WHERE code = $1",
			inviteCode).Scan(&inviteID, &inviteEmail, &usedBy, &expiresAt)
		if err != nil {
			ErrorJSON(w, http.StatusBadRequest, "Invalid invite code.")
			return
		}
		if usedBy != nil {
			ErrorJSON(w, http.StatusBadRequest, "This invite code has already been used.")
			return
		}
		if expiresAt != nil && time.Now().After(*expiresAt) {
			ErrorJSON(w, http.StatusBadRequest, "This invite code has expired.")
			return
		}
		if inviteEmail != nil && *inviteEmail != "" && strings.ToLower(*inviteEmail) != emailClean {
			ErrorJSON(w, http.StatusBadRequest, "This invite code is for a different email address.")
			return
		}
		sess.Set("pendingInviteCode", inviteCode)
	}

	var exists bool
	err := h.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", emailClean).Scan(&exists)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not register.")
		return
	}
	if exists {
		ErrorJSON(w, http.StatusConflict, "Account already exists.")
		return
	}

	if timezone == "" {
		timezone = middleware.GetClientTimezone(r)
	}
	if timezone == "" {
		timezone = "UTC"
	}

	hash, err := hashPassword(password)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not register.")
		return
	}

	sess.Set("pendingRegistration", map[string]any{
		"email":      emailClean,
		"hash":       hash,
		"timezone":   timezone,
		"createdAt":  time.Now().Unix(),
	})

	c := service.GenerateCaptcha()
	sess.Set("captchaAnswer", c.Text)
	JSON(w, http.StatusOK, map[string]any{"ok": true, "requireCaptcha": true, "captchaSvg": c.Data})
}

func (h *AuthHandler) registerCaptcha(w http.ResponseWriter, r *http.Request, sess *session.Session, captcha string) {
	pendingRaw := sess.Get("pendingRegistration")
	pending, ok := pendingRaw.(map[string]any)
	if !ok || pending == nil {
		ErrorJSON(w, http.StatusBadRequest, "Registration session expired.")
		return
	}

	emailClean, _ := pending["email"].(string)
	hash, _ := pending["hash"].(string)
	timezone, _ := pending["timezone"].(string)
	createdAt, _ := pending["createdAt"].(float64)

	if emailClean == "" || hash == "" || (createdAt > 0 && time.Since(time.Unix(int64(createdAt), 0)) > 30*time.Minute) {
		sess.Delete("pendingRegistration")
		ErrorJSON(w, http.StatusBadRequest, "Registration session expired.")
		return
	}

	captchaAnswer := sess.GetString("captchaAnswer")
	if !service.VerifyCaptcha(captchaAnswer, captcha) {
		c := service.GenerateCaptcha()
		sess.Set("captchaAnswer", c.Text)
		JSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid captcha.", "captchaSvg": c.Data})
		return
	}
	sess.Delete("captchaAnswer")

	var exists bool
	err := h.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", emailClean).Scan(&exists)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not register.")
		return
	}
	if exists {
		sess.Delete("pendingRegistration")
		ErrorJSON(w, http.StatusConflict, "Account already exists.")
		return
	}

	// Check if invite mode is active — reject if no invite code was provided
	invCode := sess.GetString("pendingInviteCode")
	if invCode == "" && h.getRegistrationMode(r) == "invite" {
		sess.Delete("pendingRegistration")
		ErrorJSON(w, http.StatusForbidden, "Registration requires an invite code.")
		return
	}

	// Re-validate and atomically claim invite code before creating user
	if invCode != "" {
		tag, err := h.Pool.Exec(r.Context(),
			`UPDATE invite_codes SET used_by = -1, used_at = NOW()
			 WHERE code = $1 AND used_by IS NULL
			   AND (expires_at IS NULL OR expires_at > NOW())`, invCode)
		if err != nil || tag.RowsAffected() == 0 {
			sess.Delete("pendingRegistration")
			sess.Delete("pendingInviteCode")
			ErrorJSON(w, http.StatusBadRequest, "Invite code is no longer valid.")
			return
		}
	}

	finalizeInvite := func(userID int) {
		if invCode != "" {
			h.Pool.Exec(r.Context(),
				"UPDATE invite_codes SET used_by = $1 WHERE code = $2", userID, invCode)
			sess.Delete("pendingInviteCode")
		}
	}

	if h.Email.IsConfigured() {
		var userID int
		err := h.Pool.QueryRow(r.Context(),
			`INSERT INTO users (email, password_hash, timezone, email_verified, macros_enabled) VALUES ($1, $2, $3, FALSE, $4) RETURNING id`,
			emailClean, hash, timezone, `{"calories": true}`,
		).Scan(&userID)
		if err != nil {
			slog.Error("registration failed", "error", err)
			ErrorJSON(w, http.StatusInternalServerError, "Could not register.")
			return
		}
		finalizeInvite(userID)
		code := service.GenerateResetCode()
		if _, err := h.Pool.Exec(r.Context(),
			"INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
			userID, code, time.Now().Add(30*time.Minute)); err != nil {
			slog.Warn("failed to insert verification token during registration", "error", err, "user_id", userID)
		}
		h.Email.SendVerificationEmail(emailClean, code)
		sess.Delete("pendingRegistration")
		sess.Set("verifyEmail", emailClean)
		JSON(w, http.StatusOK, map[string]any{"ok": true, "requireVerification": true})
	} else {
		var userID int
		err := h.Pool.QueryRow(r.Context(),
			`INSERT INTO users (email, password_hash, timezone, email_verified, macros_enabled) VALUES ($1, $2, $3, TRUE, $4) RETURNING id`,
			emailClean, hash, timezone, `{"calories": true}`,
		).Scan(&userID)
		if err != nil {
			slog.Error("registration failed", "error", err)
			ErrorJSON(w, http.StatusInternalServerError, "Could not register.")
			return
		}
		finalizeInvite(userID)
		sess.Delete("pendingRegistration")
		sess.SetUserID(userID)
		OkJSON(w)
	}
}

// Logout handles POST /api/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess := session.GetSession(r)
	h.SessionStore.Destroy(w, r, sess)
	OkJSON(w)
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
		JSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid captcha.", "captchaSvg": c.Data})
		return
	}

	email := strings.ToLower(strings.TrimSpace(body.Email))
	if email == "" {
		ErrorJSON(w, http.StatusBadRequest, "Email is required.")
		return
	}

	var userID int
	var userEmail string
	err := h.Pool.QueryRow(r.Context(), "SELECT id, email FROM users WHERE email = $1", email).Scan(&userID, &userEmail)
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
		} else {
			h.Email.SendPasswordResetEmail(userEmail, code)
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
			ErrorJSON(w, http.StatusBadRequest, "Invalid or expired code.")
			return
		}
		sess.Set("resetCodeVerified", true)
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
	if _, err := h.Pool.Exec(r.Context(), "UPDATE users SET password_hash = $1 WHERE id = $2", hash, userID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not reset password.")
		return
	}
	if _, err := h.Pool.Exec(r.Context(), "UPDATE password_reset_tokens SET used = TRUE WHERE id = $1", tokenID); err != nil {
		slog.Error("failed to mark password reset token as used", "error", err, "token_id", tokenID)
	}

	sess.Delete("resetEmail")
	sess.Delete("resetCodeVerified")
	sess.Delete("resetTokenId")
	sess.Delete("resetUserId")
	OkJSON(w)
}

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

	var tokenID, userID int
	var expiresAt time.Time
	err := h.Pool.QueryRow(r.Context(), `
		SELECT evt.id, evt.user_id, evt.expires_at
		FROM email_verification_tokens evt
		JOIN users u ON u.id = evt.user_id
		WHERE u.email = $1 AND evt.token = $2 AND evt.used = FALSE
		ORDER BY evt.created_at DESC LIMIT 1`,
		email, code).Scan(&tokenID, &userID, &expiresAt)

	if err != nil || time.Now().After(expiresAt) {
		sess.Set("verifyAttempts", attempts+1)
		ErrorJSON(w, http.StatusBadRequest, "Invalid or expired code.")
		return
	}

	tx, txErr := h.Pool.Begin(r.Context())
	if txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not verify email.")
		return
	}
	defer tx.Rollback(r.Context())

	if _, txErr = tx.Exec(r.Context(), "UPDATE email_verification_tokens SET used = TRUE WHERE id = $1", tokenID); txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not verify email.")
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

// Captcha handles GET /api/auth/captcha
func (h *AuthHandler) Captcha(w http.ResponseWriter, r *http.Request) {
	c := service.GenerateCaptcha()
	sess := session.GetSession(r)
	sess.Set("captchaAnswer", c.Text)
	JSON(w, http.StatusOK, map[string]any{"svg": c.Data})
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

	var tokenID int
	var newEmail string
	var expiresAt time.Time
	err := h.Pool.QueryRow(r.Context(), `
		SELECT id, new_email, expires_at
		FROM email_verification_tokens
		WHERE user_id = $1 AND token = $2 AND used = FALSE AND new_email IS NOT NULL
		ORDER BY created_at DESC LIMIT 1`,
		user.ID, code).Scan(&tokenID, &newEmail, &expiresAt)

	if err != nil || time.Now().After(expiresAt) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid or expired verification code.")
		return
	}

	tx, txErr := h.Pool.Begin(r.Context())
	if txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not change email.")
		return
	}
	defer tx.Rollback(r.Context())

	if _, txErr = tx.Exec(r.Context(), "UPDATE users SET email = $1 WHERE id = $2", newEmail, user.ID); txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not change email.")
		return
	}
	if _, txErr = tx.Exec(r.Context(), "UPDATE email_verification_tokens SET used = TRUE WHERE id = $1", tokenID); txErr != nil {
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

// --- helpers ---

func verifyPassword(hash, password string) (bool, error) {
	if hash == "" || password == "" {
		return false, nil
	}
	if strings.HasPrefix(hash, "$2b$") || strings.HasPrefix(hash, "$2a$") {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		return err == nil, nil
	}
	// Argon2 format: $argon2id$...
	return verifyArgon2(hash, password)
}

func verifyArgon2(hash, password string) (bool, error) {
	// Use alexedwards/argon2id for verification
	match, err := argon2idCompareHashAndPassword(hash, password)
	return match, err
}

func hashPassword(password string) (string, error) {
	return argon2idCreateHash(password)
}

func migratePasswordHash(pool *pgxpool.Pool, userID int, password string) {
	hash, err := hashPassword(password)
	if err != nil {
		return
	}
	if _, err := pool.Exec(context.Background(), "UPDATE users SET password_hash = $1 WHERE id = $2", hash, userID); err != nil {
		slog.Error("failed to migrate password hash", "error", err, "user_id", userID)
	}
}

func recordLoginFailure(sess *session.Session) {
	attempts, _ := sess.GetInt("loginFailedAttempts")
	sess.Set("loginFailedAttempts", attempts+1)
}

func verifyAndUseBackupCodeForLogin(r *http.Request, pool *pgxpool.Pool, userID int, code string) bool {
	return verifyAndMarkBackupCode(r, pool, userID, code)
}

// verifyAndMarkBackupCode atomically verifies a backup code and marks it used.
// It reads all unused codes, finds a match in-memory, then uses an atomic UPDATE
// with a WHERE used = FALSE condition to prevent race conditions.
func verifyAndMarkBackupCode(r *http.Request, pool *pgxpool.Pool, userID int, code string) bool {
	rows, err := pool.Query(r.Context(),
		"SELECT id, code_hash FROM totp_backup_codes WHERE user_id = $1 AND used = FALSE", userID)
	if err != nil {
		return false
	}
	defer rows.Close()

	// Collect all codes first, then close the result set before updating
	type codeEntry struct {
		id   int
		hash string
	}
	var codes []codeEntry
	for rows.Next() {
		var c codeEntry
		if err := rows.Scan(&c.id, &c.hash); err != nil {
			continue
		}
		codes = append(codes, c)
	}
	rows.Close()

	for _, c := range codes {
		if service.VerifyBackupCode(code, c.hash) {
			// Atomic: only marks used if still unused (prevents race condition)
			tag, err := pool.Exec(r.Context(),
				"UPDATE totp_backup_codes SET used = TRUE WHERE id = $1 AND used = FALSE", c.id)
			if err != nil || tag.RowsAffected() == 0 {
				return false // Already used by a concurrent request
			}
			return true
		}
	}
	return false
}

func replyWithCaptchaIfNeeded(w http.ResponseWriter, sess *session.Session) {
	attempts, _ := sess.GetInt("loginFailedAttempts")
	resp := map[string]any{"ok": false, "error": "Invalid credentials."}
	if attempts >= 3 {
		c := service.GenerateCaptcha()
		sess.Set("captchaAnswer", c.Text)
		resp["captchaSvg"] = c.Data
		resp["requireCaptcha"] = true
	}
	JSON(w, http.StatusUnauthorized, resp)
}
