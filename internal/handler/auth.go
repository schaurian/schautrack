package handler

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

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
		newSess.Set("auth_method", "password")
		session.SetSession(r, newSess)
		OkJSON(w)
		return
	}

	if body.Email == "" || body.Password == "" {
		ErrorJSON(w, http.StatusBadRequest, "Email and password are required.")
		return
	}

	captchaAnswer := sess.GetString("captchaAnswer")
	if captchaAnswer != "" {
		if !service.VerifyCaptcha(captchaAnswer, body.Captcha) {
			c := service.GenerateCaptcha()
			sess.Set("captchaAnswer", c.Text)
			JSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid captcha.", "captchaSvg": c.Data, "requireCaptcha": true})
			return
		}
		sess.Delete("captchaAnswer")
	}

	email := strings.ToLower(strings.TrimSpace(body.Email))
	var userID int
	var passwordHash string
	var emailVerified bool
	var totpEnabled bool
	err := h.Pool.QueryRow(r.Context(), "SELECT id, password_hash, email_verified, totp_enabled FROM users WHERE email = $1", email).
		Scan(&userID, &passwordHash, &emailVerified, &totpEnabled)
	if err != nil {
		recordLoginFailure(sess)
		replyWithCaptchaIfNeeded(w, sess)
		return
	}

	valid, _ := verifyPassword(passwordHash, body.Password)
	if !valid {
		recordLoginFailure(sess)
		replyWithCaptchaIfNeeded(w, sess)
		return
	}

	// Migrate bcrypt → argon2id
	if strings.HasPrefix(passwordHash, "$2b$") || strings.HasPrefix(passwordHash, "$2a$") {
		go migratePasswordHash(h.Pool, userID, body.Password)
	}

	if !emailVerified && h.Email.IsConfigured() {
		code := service.GenerateResetCode()
		if _, err := h.Pool.Exec(r.Context(),
			"INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
			userID, code, time.Now().Add(30*time.Minute)); err != nil {
			slog.Warn("failed to insert verification token during login", "error", err, "user_id", userID)
		}
		h.Email.SendVerificationEmail(email, code)
		sess.Set("verifyEmail", email)
		JSON(w, http.StatusOK, map[string]any{"ok": true, "requireVerification": true})
		return
	}

	if totpEnabled {
		sess.Set("pendingUserId", userID)
		resp := map[string]any{"ok": true, "requireToken": true}
		if h.Email.IsConfigured() {
			resp["canReset2fa"] = true
		}
		JSON(w, http.StatusOK, resp)
		return
	}

	newSess, err := h.SessionStore.Regenerate(r, sess)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Session error.")
		return
	}
	newSess.SetUserID(userID)
	newSess.Set("auth_method", "password")
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

func (h *AuthHandler) isRegistrationEnabled(r *http.Request) bool {
	result := h.Settings.GetEffectiveSetting(r.Context(), "enable_registration", h.Cfg.EnableRegistration)
	if result.Value != nil && *result.Value == "false" {
		return false
	}
	return true
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
	if !h.isRegistrationEnabled(r) {
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
	if invCode == "" && !h.isRegistrationEnabled(r) {
		sess.Delete("pendingRegistration")
		ErrorJSON(w, http.StatusForbidden, "Registration requires an invite code.")
		return
	}

	// Create user and claim invite code atomically in a transaction
	tx, txErr := h.Pool.Begin(r.Context())
	if txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not register.")
		return
	}
	defer tx.Rollback(r.Context())

	var userID int
	err = tx.QueryRow(r.Context(),
		`INSERT INTO users (email, password_hash, timezone, email_verified, macros_enabled) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		emailClean, hash, timezone, !h.Email.IsConfigured(), `{"calories": true}`,
	).Scan(&userID)
	if err != nil {
		slog.Error("registration failed", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Could not register.")
		return
	}

	// Claim invite code atomically (now that user exists, FK is satisfied)
	if invCode != "" {
		tag, claimErr := tx.Exec(r.Context(),
			`UPDATE invite_codes SET used_by = $1, used_at = NOW()
			 WHERE code = $2 AND used_by IS NULL
			   AND (expires_at IS NULL OR expires_at > NOW())`, userID, invCode)
		if claimErr != nil || tag.RowsAffected() == 0 {
			sess.Delete("pendingRegistration")
			sess.Delete("pendingInviteCode")
			ErrorJSON(w, http.StatusBadRequest, "Invite code is no longer valid.")
			return
		}
		sess.Delete("pendingInviteCode")
	}

	if txErr = tx.Commit(r.Context()); txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not register.")
		return
	}

	sess.Delete("pendingRegistration")

	if h.Email.IsConfigured() {
		code := service.GenerateResetCode()
		if _, err := h.Pool.Exec(r.Context(),
			"INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
			userID, code, time.Now().Add(30*time.Minute)); err != nil {
			slog.Warn("failed to insert verification token during registration", "error", err, "user_id", userID)
		}
		h.Email.SendVerificationEmail(emailClean, code)
		sess.Set("verifyEmail", emailClean)
		JSON(w, http.StatusOK, map[string]any{"ok": true, "requireVerification": true})
	} else {
		sess.SetUserID(userID)
		sess.Set("auth_method", "password")
		OkJSON(w)
	}
}

// Logout handles POST /api/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess := session.GetSession(r)
	h.SessionStore.Destroy(w, r, sess)
	OkJSON(w)
}
