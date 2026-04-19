package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/session"
)

type OIDCHandler struct {
	Pool          *pgxpool.Pool
	Cfg           *config.Config
	Settings      *database.SettingsCache
	SessionStore  *session.Store
	verifiers     map[string]*oidc.IDTokenVerifier
	oauth2Configs map[string]*oauth2.Config
}

func NewOIDCHandler(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, settings *database.SettingsCache, store *session.Store) (*OIDCHandler, error) {
	h := &OIDCHandler{
		Pool:          pool,
		Cfg:           cfg,
		Settings:      settings,
		SessionStore:  store,
		verifiers:     make(map[string]*oidc.IDTokenVerifier),
		oauth2Configs: make(map[string]*oauth2.Config),
	}

	for _, p := range cfg.OIDCProviders {
		provider, err := oidc.NewProvider(ctx, p.IssuerURL)
		if err != nil {
			slog.Error("failed to initialize OIDC provider", "name", p.Name, "error", err)
			continue
		}

		redirectURL := cfg.OIDCRedirectURL
		if redirectURL == "" && cfg.BaseURL != "" {
			redirectURL = strings.TrimRight(cfg.BaseURL, "/") + "/auth/oidc/" + p.Name + "/callback"
		}

		h.verifiers[p.Name] = provider.Verifier(&oidc.Config{ClientID: p.ClientID})
		h.oauth2Configs[p.Name] = &oauth2.Config{
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		}
	}

	return h, nil
}

func (h *OIDCHandler) Login(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	oauthCfg, ok := h.oauth2Configs[providerName]
	if !ok {
		http.Error(w, "Unknown provider", http.StatusNotFound)
		return
	}

	state, err := generateRandomString(32)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := generateRandomString(32)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	sess := session.GetSession(r)
	sess.Set("oidc_state", state)
	sess.Set("oidc_nonce", nonce)
	sess.Set("oidc_provider", providerName)

	// Check if this is a link operation (user already logged in)
	user := middleware.GetCurrentUser(r)
	if user != nil {
		sess.Set("oidc_intent", "link")
	} else {
		sess.Set("oidc_intent", "login")
	}

	url := oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce))
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *OIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	providerName := r.PathValue("provider")
	oauthCfg, ok := h.oauth2Configs[providerName]
	if !ok {
		http.Redirect(w, r, "/login?error=unknown_provider", http.StatusFound)
		return
	}
	verifier, ok := h.verifiers[providerName]
	if !ok {
		http.Redirect(w, r, "/login?error=provider_not_configured", http.StatusFound)
		return
	}

	sess := session.GetSession(r)
	savedState := sess.GetString("oidc_state")
	savedNonce := sess.GetString("oidc_nonce")
	intent := sess.GetString("oidc_intent")

	// Clean up session
	sess.Delete("oidc_state")
	sess.Delete("oidc_nonce")
	sess.Delete("oidc_provider")
	sess.Delete("oidc_intent")

	if r.URL.Query().Get("state") != savedState || savedState == "" {
		http.Redirect(w, r, "/login?error=invalid_state", http.StatusFound)
		return
	}

	token, err := oauthCfg.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		slog.Error("OIDC code exchange failed", "provider", providerName, "error", err)
		http.Redirect(w, r, "/login?error=exchange_failed", http.StatusFound)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Redirect(w, r, "/login?error=no_id_token", http.StatusFound)
		return
	}

	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		slog.Error("OIDC token verification failed", "provider", providerName, "error", err)
		http.Redirect(w, r, "/login?error=verification_failed", http.StatusFound)
		return
	}

	if idToken.Nonce != savedNonce {
		http.Redirect(w, r, "/login?error=invalid_nonce", http.StatusFound)
		return
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Sub           string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Redirect(w, r, "/login?error=invalid_claims", http.StatusFound)
		return
	}
	claims.Email = strings.ToLower(strings.TrimSpace(claims.Email))

	if intent == "link" {
		h.handleLink(w, r, sess, providerName, claims.Sub, claims.Email)
		return
	}

	h.handleLogin(w, r, sess, providerName, claims.Sub, claims.Email)
}

func (h *OIDCHandler) handleLogin(w http.ResponseWriter, r *http.Request, sess *session.Session, provider, subject, email string) {
	ctx := r.Context()

	// 1. Look up by OIDC account
	account, err := service.FindOIDCAccount(ctx, h.Pool, provider, subject)
	if err == nil && account != nil {
		newSess, _ := h.SessionStore.Regenerate(r, sess)
		session.SetSession(r, newSess)
		newSess.SetUserID(account.UserID)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// 2. Look up by email → auto-link
	if email != "" {
		var userID int
		err := h.Pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&userID)
		if err == nil {
			_ = service.CreateOIDCAccount(ctx, h.Pool, userID, provider, subject, email)
			newSess2, _ := h.SessionStore.Regenerate(r, sess)
			session.SetSession(r, newSess2)
			newSess2.SetUserID(userID)
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
	}

	// 3. Auto-create new user
	if !h.canAutoCreate(r) {
		http.Redirect(w, r, "/login?error=registration_disabled", http.StatusFound)
		return
	}

	if email == "" {
		http.Redirect(w, r, "/login?error=no_email", http.StatusFound)
		return
	}

	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		http.Redirect(w, r, "/login?error=internal", http.StatusFound)
		return
	}
	defer tx.Rollback(ctx)

	var userID int
	defaultMacros, _ := json.Marshal(map[string]bool{"calories": true})
	err = tx.QueryRow(ctx,
		`INSERT INTO users (email, email_verified, macros_enabled) VALUES ($1, true, $2) RETURNING id`,
		email, defaultMacros).Scan(&userID)
	if err != nil {
		slog.Error("OIDC auto-create user failed", "email", email, "error", err)
		http.Redirect(w, r, "/login?error=create_failed", http.StatusFound)
		return
	}

	_, err = tx.Exec(ctx,
		"INSERT INTO user_oidc_accounts (user_id, provider, subject, email) VALUES ($1, $2, $3, $4)",
		userID, provider, subject, email)
	if err != nil {
		http.Redirect(w, r, "/login?error=create_failed", http.StatusFound)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		http.Redirect(w, r, "/login?error=create_failed", http.StatusFound)
		return
	}

	newSess3, _ := h.SessionStore.Regenerate(r, sess)
	session.SetSession(r, newSess3)
	newSess3.SetUserID(userID)
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (h *OIDCHandler) handleLink(w http.ResponseWriter, r *http.Request, sess *session.Session, provider, subject, email string) {
	user := middleware.GetCurrentUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if already linked by another user
	existing, err := service.FindOIDCAccount(r.Context(), h.Pool, provider, subject)
	if err == nil && existing != nil && existing.UserID != user.ID {
		http.Redirect(w, r, "/settings?error=oidc_already_linked", http.StatusFound)
		return
	}

	_ = service.CreateOIDCAccount(r.Context(), h.Pool, user.ID, provider, subject, email)
	http.Redirect(w, r, "/settings?success=oidc_linked", http.StatusFound)
}

func (h *OIDCHandler) Unlink(w http.ResponseWriter, r *http.Request) {
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

	if !hasPass && passkeyCount == 0 && oidcCount <= 1 {
		ErrorJSON(w, http.StatusBadRequest, "Cannot unlink — you need at least one login method.")
		return
	}

	if err := service.DeleteOIDCAccount(r.Context(), h.Pool, body.ID, user.ID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to unlink.")
		return
	}

	OkJSON(w)
}

func (h *OIDCHandler) canAutoCreate(r *http.Request) bool {
	if h.Cfg.OIDCRequireInvite {
		return false
	}
	result := h.Settings.GetEffectiveSetting(r.Context(), "enable_registration", h.Cfg.EnableRegistration)
	if result.Value != nil && *result.Value == "false" {
		return h.Cfg.OIDCRequireInvite == false // OIDC bypasses invite-only unless explicitly required
	}
	return true
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
