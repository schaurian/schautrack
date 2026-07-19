package handler

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"schautrack/internal/clientip"
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

// trustProxy reports whether proxy headers may be trusted for client IP
// extraction. Nil-safe because handler tests construct AuthHandler without Cfg.
func (h *AuthHandler) trustProxy() bool {
	return h.Cfg != nil && h.Cfg.TrustProxy
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
			// Cap failed 2FA attempts per pending session (mirrors
			// stepup.go's maxStepUpFailures): the 6-digit TOTP must not be
			// brute-forceable by replaying the same pending session.
			if recordLogin2FAFailure(sess) {
				if err := h.SessionStore.Destroy(w, r, sess); err != nil {
					slog.Error("failed to destroy session on login 2FA lockout", "error", err)
				}
				JSON(w, http.StatusUnauthorized, map[string]any{
					"error":   "Too many failed attempts. Please log in again.",
					"lockout": true,
				})
				return
			}
			ErrorJSON(w, http.StatusUnauthorized, "Invalid 2FA code.")
			return
		}
		sess.Delete("pendingUserId")
		sess.Delete("login2faFailures")
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

	email := strings.ToLower(strings.TrimSpace(body.Email))
	clientAddr := clientip.FromRequest(r, h.trustProxy())

	captchaAnswer := sess.GetString("captchaAnswer")
	if captchaAnswer == "" && loginCaptchaRequired(sess, email, clientAddr) {
		// The server-side failure counters (keyed by account email and
		// client IP) demand a captcha, but this session has none in flight —
		// e.g. a client dropping its cookies between attempts to keep the
		// session counter at zero. Issue a challenge instead of processing.
		c := service.GenerateCaptcha()
		sess.Set("captchaAnswer", c.Text)
		JSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "Captcha required.", "captchaSvg": c.Data, "captchaQuestion": c.Question, "requireCaptcha": true})
		return
	}
	if captchaAnswer != "" {
		if !service.VerifyCaptcha(captchaAnswer, body.Captcha) {
			c := service.GenerateCaptcha()
			sess.Set("captchaAnswer", c.Text)
			JSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid captcha.", "captchaSvg": c.Data, "captchaQuestion": c.Question, "requireCaptcha": true})
			return
		}
		sess.Delete("captchaAnswer")
	}

	var userID int
	var passwordHash string
	var emailVerified bool
	var totpEnabled bool
	var userLanguage *string
	err := h.Pool.QueryRow(r.Context(), "SELECT id, password_hash, email_verified, totp_enabled, language FROM users WHERE email = $1", email).
		Scan(&userID, &passwordHash, &emailVerified, &totpEnabled, &userLanguage)
	if err != nil {
		// Burn the same argon2id cost as a real password check so unknown
		// emails aren't distinguishable from wrong passwords by timing.
		equalizeLoginTiming(body.Password)
		recordLoginFailure(sess)
		recordServerLoginFailure(email, clientAddr)
		replyWithCaptchaIfNeeded(w, sess, email, clientAddr)
		return
	}

	valid, _ := verifyPassword(passwordHash, body.Password)
	if !valid {
		recordLoginFailure(sess)
		recordServerLoginFailure(email, clientAddr)
		replyWithCaptchaIfNeeded(w, sess, email, clientAddr)
		return
	}

	// Correct credentials: clear the failure counters.
	clearLoginFailures(sess, email, clientAddr)

	// Migrate bcrypt → argon2id
	if strings.HasPrefix(passwordHash, "$2b$") || strings.HasPrefix(passwordHash, "$2a$") {
		go migratePasswordHash(h.Pool, userID, body.Password)
	}

	if !emailVerified && h.Email.IsConfigured() {
		code := service.GenerateResetCode()
		if _, err := h.Pool.Exec(r.Context(),
			"INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
			userID, code, time.Now().Add(30*time.Minute)); err != nil {
			slog.Error("failed to insert verification token during login", "error", err, "user_id", userID)
			ErrorJSON(w, http.StatusInternalServerError, "Could not send verification email. Please try again.")
			return
		}
		if err := h.Email.SendVerificationEmail(email, code, derefLang(userLanguage)); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not send verification email. Please try again.")
			return
		}
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
		Step          string `json:"step"`
		Email         string `json:"email"`
		Password      string `json:"password"`
		Timezone      string `json:"timezone"`
		Captcha       string `json:"captcha"`
		InviteCode    string `json:"invite_code"`
		LegalAccepted bool   `json:"legal_accepted"`
		HealthConsent bool   `json:"health_consent"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	sess := session.GetSession(r)

	switch body.Step {
	case "credentials":
		h.registerCredentials(w, r, sess, body.Email, body.Password, body.Timezone, body.InviteCode, body.LegalAccepted, body.HealthConsent)
	case "captcha":
		h.registerCaptcha(w, r, sess, body.Captcha)
	default:
		ErrorJSON(w, http.StatusBadRequest, "Invalid step.")
	}
}

func (h *AuthHandler) registerCredentials(w http.ResponseWriter, r *http.Request, sess *session.Session, email, password, timezone, inviteCode string, legalAccepted, healthConsent bool) {
	emailClean := strings.ToLower(strings.TrimSpace(email))
	if emailClean == "" || password == "" {
		ErrorJSON(w, http.StatusBadRequest, "Email and password are required.")
		return
	}
	if len(password) < 10 {
		ErrorJSON(w, http.StatusBadRequest, "Password must be at least 10 characters.")
		return
	}

	// When this instance publishes legal pages (ENABLE_LEGAL), registration
	// requires accepting the Terms/Privacy AND separately consenting to
	// health-data processing (Art. 9(2)(a) GDPR; Art. 7(2) requires the two to
	// be distinguishable). Instances without legal pages are unaffected.
	requireConsent := legalPagesEnabled(r.Context(), h.Settings)
	if requireConsent && (!legalAccepted || !healthConsent) {
		ErrorJSON(w, http.StatusBadRequest, "You must accept the Terms and Privacy Policy and consent to the processing of your health data to register.")
		return
	}

	// Gate on the configured registration mode.
	switch effectiveRegistrationMode(r.Context(), h.Settings, h.Cfg) {
	case regModeClosed:
		// Registration fully disabled — no invite code can override this.
		ErrorJSON(w, http.StatusForbidden, "Registration is disabled.")
		return
	case regModeInvite:
		// Invite-only: fail closed unless a valid, unused invite code is given.
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
		"email":     emailClean,
		"hash":      hash,
		"timezone":  timezone,
		"createdAt": time.Now().Unix(),
		// Recorded at INSERT time as legal_accepted_at/health_consent_at so
		// the controller can demonstrate consent (Art. 7(1) GDPR).
		"legalConsent": requireConsent && legalAccepted && healthConsent,
	})

	c := service.GenerateCaptcha()
	sess.Set("captchaAnswer", c.Text)
	JSON(w, http.StatusOK, map[string]any{"ok": true, "requireCaptcha": true, "captchaSvg": c.Data, "captchaQuestion": c.Question})
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
	legalConsent, _ := pending["legalConsent"].(bool)

	if emailClean == "" || hash == "" || (createdAt > 0 && time.Since(time.Unix(int64(createdAt), 0)) > 30*time.Minute) {
		sess.Delete("pendingRegistration")
		ErrorJSON(w, http.StatusBadRequest, "Registration session expired.")
		return
	}

	captchaAnswer := sess.GetString("captchaAnswer")
	if !service.VerifyCaptcha(captchaAnswer, captcha) {
		c := service.GenerateCaptcha()
		sess.Set("captchaAnswer", c.Text)
		JSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "Invalid captcha.", "captchaSvg": c.Data, "captchaQuestion": c.Question})
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

	// Re-check the registration mode at this final step — it may have changed
	// between the credentials step and now. Never create a user in a mode that
	// forbids it (fail closed).
	invCode := sess.GetString("pendingInviteCode")
	switch effectiveRegistrationMode(r.Context(), h.Settings, h.Cfg) {
	case regModeClosed:
		sess.Delete("pendingRegistration")
		sess.Delete("pendingInviteCode")
		ErrorJSON(w, http.StatusForbidden, "Registration is disabled.")
		return
	case regModeInvite:
		if invCode == "" {
			sess.Delete("pendingRegistration")
			ErrorJSON(w, http.StatusForbidden, "Registration requires an invite code.")
			return
		}
	}

	// Generate the verification code before opening the transaction so the
	// token row is created atomically with the user row: if the token INSERT
	// fails, the whole registration rolls back instead of leaving an
	// unverified user with no token for CleanExpiredTokens to reap.
	emailConfigured := h.Email.IsConfigured()
	var verifyCode string
	if emailConfigured {
		verifyCode = service.GenerateResetCode()
	}

	// Create user and claim invite code atomically in a transaction
	tx, txErr := h.Pool.Begin(r.Context())
	if txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not register.")
		return
	}
	defer tx.Rollback(r.Context())

	// Consent timestamps are NULL unless this registration recorded consent
	// (legal pages enabled + both checkboxes accepted at the credentials step).
	var consentAt *time.Time
	if legalConsent {
		now := time.Now()
		consentAt = &now
	}

	var userID int
	err = tx.QueryRow(r.Context(),
		`INSERT INTO users (email, password_hash, timezone, email_verified, macros_enabled, legal_accepted_at, health_consent_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		emailClean, hash, timezone, !h.Email.IsConfigured(), `{"calories": true}`, consentAt, consentAt,
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

	if emailConfigured {
		if _, err := tx.Exec(r.Context(),
			"INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
			userID, verifyCode, time.Now().Add(30*time.Minute)); err != nil {
			slog.Error("failed to insert verification token during registration", "error", err)
			ErrorJSON(w, http.StatusInternalServerError, "Could not register.")
			return
		}
	}

	if txErr = tx.Commit(r.Context()); txErr != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not register.")
		return
	}

	sess.Delete("pendingRegistration")

	if emailConfigured {
		// Email send stays outside the transaction — the account exists
		// either way, and login/resend can retry the verification email.
		sess.Set("verifyEmail", emailClean)
		// No language preference exists yet at registration time (the user
		// hasn't set one), so pass "" and let it fall back to "en".
		if err := h.Email.SendVerificationEmail(emailClean, verifyCode, ""); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not send verification email. Please try again.")
			return
		}
		JSON(w, http.StatusOK, map[string]any{"ok": true, "requireVerification": true})
	} else {
		// Rotate the session ID on privilege elevation (session fixation),
		// mirroring the login path above.
		newSess, regenErr := h.SessionStore.Regenerate(r, sess)
		if regenErr != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not register.")
			return
		}
		newSess.SetUserID(userID)
		newSess.Set("auth_method", "password")
		session.SetSession(r, newSess)
		OkJSON(w)
	}
}

// Logout handles POST /api/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sess := session.GetSession(r)
	h.SessionStore.Destroy(w, r, sess)
	OkJSON(w)
}
