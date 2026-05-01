package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/session"
)

// StepUpHandler implements the elevation endpoints used by sensitive auth-method
// changes. A successful call sets the session's step_up_at timestamp, granting
// the client a session.StepUpTTL window during which gated endpoints accept
// requests without re-authenticating.
type StepUpHandler struct {
	Pool     *pgxpool.Pool
	WebAuthn *webauthn.WebAuthn
}

// PasswordTOTP handles POST /api/auth/step-up
// Body: {password, token?}. If the user has TOTP enabled, token is required
// and may be either the current TOTP code or a backup code.
func (h *StepUpHandler) PasswordTOTP(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	if user == nil {
		ErrorJSON(w, http.StatusUnauthorized, "Not authenticated")
		return
	}
	var body struct {
		Password string `json:"password"`
		Token    string `json:"token"`
	}
	if err := ReadJSON(r, &body); err != nil || body.Password == "" {
		ErrorJSON(w, http.StatusBadRequest, "Password is required.")
		return
	}

	var hash string
	if err := h.Pool.QueryRow(r.Context(),
		"SELECT COALESCE(password_hash, '') FROM users WHERE id = $1", user.ID,
	).Scan(&hash); err != nil || hash == "" {
		ErrorJSON(w, http.StatusBadRequest, "No password set on this account.")
		return
	}
	valid, _ := verifyPassword(hash, body.Password)
	if !valid {
		ErrorJSON(w, http.StatusUnauthorized, "Invalid credentials.")
		return
	}

	if user.TOTPEnabled && user.TOTPSecret != nil {
		if body.Token == "" {
			ErrorJSON(w, http.StatusUnauthorized, "2FA code is required.")
			return
		}
		if !totp.Validate(body.Token, *user.TOTPSecret) &&
			!verifyAndUseBackupCodeForLogin(r, h.Pool, user.ID, body.Token) {
			ErrorJSON(w, http.StatusUnauthorized, "Invalid 2FA code.")
			return
		}
	}

	sess := session.GetSession(r)
	sess.MarkStepUp()
	OkJSON(w)
}

// PasskeyBegin handles POST /api/auth/step-up/passkey/begin
// Returns assertion options scoped to the current user's credentials only
// (non-discoverable — we already know who's logged in).
func (h *StepUpHandler) PasskeyBegin(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	if user == nil {
		ErrorJSON(w, http.StatusUnauthorized, "Not authenticated")
		return
	}
	existing, _ := service.ListPasskeys(r.Context(), h.Pool, user.ID)
	if len(existing) == 0 {
		ErrorJSON(w, http.StatusBadRequest, "No passkey registered.")
		return
	}
	wUser := &webauthnUser{
		id:          user.ID,
		email:       user.Email,
		credentials: passkeysToCredentials(existing),
	}
	options, sessionData, err := h.WebAuthn.BeginLogin(wUser)
	if err != nil {
		slog.Error("step-up BeginLogin failed", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to start step-up.")
		return
	}
	sess := session.GetSession(r)
	sb, _ := json.Marshal(sessionData)
	sess.Set("webauthn_step_up", string(sb))
	JSON(w, http.StatusOK, options)
}

// PasskeyFinish handles POST /api/auth/step-up/passkey/finish
func (h *StepUpHandler) PasskeyFinish(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	if user == nil {
		ErrorJSON(w, http.StatusUnauthorized, "Not authenticated")
		return
	}
	sess := session.GetSession(r)
	stored := sess.GetString("webauthn_step_up")
	if stored == "" {
		ErrorJSON(w, http.StatusBadRequest, "No step-up in progress.")
		return
	}
	sess.Delete("webauthn_step_up")

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(stored), &sessionData); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid session data.")
		return
	}
	existing, _ := service.ListPasskeys(r.Context(), h.Pool, user.ID)
	wUser := &webauthnUser{
		id:          user.ID,
		email:       user.Email,
		credentials: passkeysToCredentials(existing),
	}
	credential, err := h.WebAuthn.FinishLogin(wUser, sessionData, r)
	if err != nil {
		slog.Error("step-up FinishLogin failed", "error", err)
		ErrorJSON(w, http.StatusUnauthorized, "Step-up failed.")
		return
	}
	_ = service.UpdatePasskeyUsage(r.Context(), h.Pool, credential.ID,
		int(credential.Authenticator.SignCount), credential.Flags.BackupState)

	sess.MarkStepUp()
	OkJSON(w)
}
