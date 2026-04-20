package handler

import (
	"encoding/binary"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/session"
)

type PasskeyHandler struct {
	Pool         *pgxpool.Pool
	WebAuthn     *webauthn.WebAuthn
	SessionStore *session.Store
}

// webauthnUser adapts our user model to go-webauthn's User interface.
type webauthnUser struct {
	id          int
	email       string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(u.id))
	return b
}

func (u *webauthnUser) WebAuthnName() string        { return u.email }
func (u *webauthnUser) WebAuthnDisplayName() string  { return u.email }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func passkeysToCredentials(records []service.PasskeyRecord) []webauthn.Credential {
	creds := make([]webauthn.Credential, len(records))
	for i, r := range records {
		var transports []protocol.AuthenticatorTransport
		if r.Transports != "" {
			for _, t := range strings.Split(r.Transports, ",") {
				transports = append(transports, protocol.AuthenticatorTransport(t))
			}
		}
		creds[i] = webauthn.Credential{
			ID:              r.CredentialID,
			PublicKey:       r.PublicKey,
			AttestationType: r.AttestationType,
			Transport:       transports,
			Authenticator: webauthn.Authenticator{
				SignCount: uint32(r.SignCount),
				AAGUID:    r.AAGUID,
			},
		}
	}
	return creds
}

// RegisterBegin starts WebAuthn registration for the current user.
func (h *PasskeyHandler) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	if user == nil {
		ErrorJSON(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	count, _ := service.CountPasskeys(r.Context(), h.Pool, user.ID)
	if count >= service.MaxPasskeys {
		ErrorJSON(w, http.StatusBadRequest, "Maximum number of passkeys reached.")
		return
	}

	existing, _ := service.ListPasskeys(r.Context(), h.Pool, user.ID)
	wUser := &webauthnUser{
		id:          user.ID,
		email:       user.Email,
		credentials: passkeysToCredentials(existing),
	}

	excludeList := make([]protocol.CredentialDescriptor, len(wUser.credentials))
	for i, c := range wUser.credentials {
		excludeList[i] = protocol.CredentialDescriptor{
			Type:            protocol.PublicKeyCredentialType,
			CredentialID:    c.ID,
			Transport:       c.Transport,
		}
	}

	options, sessionData, err := h.WebAuthn.BeginRegistration(wUser,
		webauthn.WithExclusions(excludeList),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		slog.Error("WebAuthn BeginRegistration failed", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to start passkey registration.")
		return
	}

	sess := session.GetSession(r)
	sessionBytes, _ := json.Marshal(sessionData)
	sess.Set("webauthn_registration", string(sessionBytes))

	JSON(w, http.StatusOK, options)
}

// RegisterFinish completes WebAuthn registration.
func (h *PasskeyHandler) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	if user == nil {
		ErrorJSON(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	sess := session.GetSession(r)
	sessionStr := sess.GetString("webauthn_registration")
	if sessionStr == "" {
		ErrorJSON(w, http.StatusBadRequest, "No registration in progress.")
		return
	}
	sess.Delete("webauthn_registration")

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionStr), &sessionData); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid session data.")
		return
	}

	existing, _ := service.ListPasskeys(r.Context(), h.Pool, user.ID)
	wUser := &webauthnUser{
		id:          user.ID,
		email:       user.Email,
		credentials: passkeysToCredentials(existing),
	}

	credential, err := h.WebAuthn.FinishRegistration(wUser, sessionData, r)
	if err != nil {
		slog.Error("WebAuthn FinishRegistration failed", "error", err)
		ErrorJSON(w, http.StatusBadRequest, "Passkey registration failed.")
		return
	}

	// Get name from query parameter or use default
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 50 {
		name = name[:50]
	}

	var transports []string
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}

	err = service.CreatePasskey(r.Context(), h.Pool, user.ID,
		credential.ID, credential.PublicKey, credential.AttestationType,
		strings.Join(transports, ","), name,
		int(credential.Authenticator.SignCount), credential.Authenticator.AAGUID)
	if err != nil {
		slog.Error("Failed to store passkey", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to save passkey.")
		return
	}

	OkJSON(w)
}

// LoginBegin starts WebAuthn assertion for login (no user context needed).
func (h *PasskeyHandler) LoginBegin(w http.ResponseWriter, r *http.Request) {
	options, sessionData, err := h.WebAuthn.BeginDiscoverableLogin()
	if err != nil {
		slog.Error("WebAuthn BeginDiscoverableLogin failed", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to start passkey login.")
		return
	}

	sess := session.GetSession(r)
	sessionBytes, _ := json.Marshal(sessionData)
	sess.Set("webauthn_login", string(sessionBytes))

	JSON(w, http.StatusOK, options)
}

// LoginFinish completes WebAuthn assertion and logs in the user.
func (h *PasskeyHandler) LoginFinish(w http.ResponseWriter, r *http.Request) {
	sess := session.GetSession(r)
	sessionStr := sess.GetString("webauthn_login")
	if sessionStr == "" {
		ErrorJSON(w, http.StatusBadRequest, "No login in progress.")
		return
	}
	sess.Delete("webauthn_login")

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(sessionStr), &sessionData); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid session data.")
		return
	}

	// Discoverable login: the handler function resolves the user from the credential
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		record, err := service.FindPasskeyByCredentialID(r.Context(), h.Pool, rawID)
		if err != nil {
			return nil, err
		}
		allPasskeys, _ := service.ListPasskeys(r.Context(), h.Pool, record.UserID)

		var email string
		_ = h.Pool.QueryRow(r.Context(), "SELECT email FROM users WHERE id = $1", record.UserID).Scan(&email)

		return &webauthnUser{
			id:          record.UserID,
			email:       email,
			credentials: passkeysToCredentials(allPasskeys),
		}, nil
	}

	credential, err := h.WebAuthn.FinishDiscoverableLogin(handler, sessionData, r)
	if err != nil {
		slog.Error("WebAuthn FinishDiscoverableLogin failed", "error", err)
		ErrorJSON(w, http.StatusUnauthorized, "Passkey login failed.")
		return
	}

	// Find the user from the credential
	record, err := service.FindPasskeyByCredentialID(r.Context(), h.Pool, credential.ID)
	if err != nil {
		ErrorJSON(w, http.StatusUnauthorized, "Passkey not found.")
		return
	}

	// Update sign count and last used
	_ = service.UpdatePasskeyUsage(r.Context(), h.Pool, credential.ID, int(credential.Authenticator.SignCount))

	// Log in — skip 2FA (passkeys are inherently MFA)
	newSess, _ := h.SessionStore.Regenerate(r, sess)
	session.SetSession(r, newSess)
	newSess.SetUserID(record.UserID)
	newSess.Set("auth_method", "passkey")

	OkJSON(w)
}

// Delete removes a passkey.
func (h *PasskeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	if user == nil {
		ErrorJSON(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	var body struct {
		ID int `json:"id"`
	}
	if err := ReadJSON(r, &body); err != nil || body.ID == 0 {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	// Safety: ensure user keeps at least one auth method
	hasPass, _ := service.HasPassword(r.Context(), h.Pool, user.ID)
	passkeyCount, _ := service.CountPasskeys(r.Context(), h.Pool, user.ID)
	oidcCount, _ := service.CountOIDCAccounts(r.Context(), h.Pool, user.ID)

	if !hasPass && oidcCount == 0 && passkeyCount <= 1 {
		ErrorJSON(w, http.StatusBadRequest, "Cannot delete — you need at least one login method.")
		return
	}

	if err := service.DeletePasskey(r.Context(), h.Pool, body.ID, user.ID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to delete passkey.")
		return
	}

	OkJSON(w)
}

// Rename changes a passkey's name.
func (h *PasskeyHandler) Rename(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	if user == nil {
		ErrorJSON(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	var body struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	}
	if err := ReadJSON(r, &body); err != nil || body.ID == 0 {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 50 {
		ErrorJSON(w, http.StatusBadRequest, "Name must be 1-50 characters.")
		return
	}

	if err := service.RenamePasskey(r.Context(), h.Pool, body.ID, user.ID, body.Name); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to rename passkey.")
		return
	}

	OkJSON(w)
}

// List returns the user's passkeys.
func (h *PasskeyHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	if user == nil {
		ErrorJSON(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	passkeys, err := service.ListPasskeys(r.Context(), h.Pool, user.ID)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to list passkeys.")
		return
	}

	type passkeyItem struct {
		ID         int     `json:"id"`
		Name       string  `json:"name"`
		CreatedAt  string  `json:"createdAt"`
		LastUsedAt *string `json:"lastUsedAt"`
	}

	items := make([]passkeyItem, len(passkeys))
	for i, p := range passkeys {
		item := passkeyItem{
			ID:        p.ID,
			Name:      p.Name,
			CreatedAt: p.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
		if p.LastUsedAt != nil {
			s := p.LastUsedAt.Format("2006-01-02T15:04:05Z")
			item.LastUsedAt = &s
		}
		items[i] = item
	}

	JSON(w, http.StatusOK, map[string]any{"ok": true, "passkeys": items})
}
