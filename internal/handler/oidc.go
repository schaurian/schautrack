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
	Pool         *pgxpool.Pool
	Cfg          *config.Config
	Settings     *database.SettingsCache
	SessionStore *session.Store
	verifier     *oidc.IDTokenVerifier
	oauth2Config *oauth2.Config
	providerSlug string
}

func NewOIDCHandler(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, settings *database.SettingsCache, store *session.Store) (*OIDCHandler, error) {
	if cfg.OIDC == nil {
		return nil, nil
	}
	c := cfg.OIDC
	provider, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, err
	}
	redirectURL := cfg.OIDCRedirectURL
	if redirectURL == "" && cfg.BaseURL != "" {
		redirectURL = strings.TrimRight(cfg.BaseURL, "/") + "/auth/oidc/callback"
	}
	return &OIDCHandler{
		Pool:         pool,
		Cfg:          cfg,
		Settings:     settings,
		SessionStore: store,
		verifier:     provider.Verifier(&oidc.Config{ClientID: c.ClientID}),
		oauth2Config: &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		providerSlug: c.Slug,
	}, nil
}

func (h *OIDCHandler) Login(w http.ResponseWriter, r *http.Request) {
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

	// Check if this is a link operation (user already logged in)
	user := middleware.GetCurrentUser(r)
	if user != nil {
		sess.Set("oidc_intent", "link")
	} else {
		sess.Set("oidc_intent", "login")
	}

	url := h.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *OIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	sess := session.GetSession(r)
	savedState := sess.GetString("oidc_state")
	savedNonce := sess.GetString("oidc_nonce")
	intent := sess.GetString("oidc_intent")

	// Clean up session
	sess.Delete("oidc_state")
	sess.Delete("oidc_nonce")
	sess.Delete("oidc_intent")

	if r.URL.Query().Get("state") != savedState || savedState == "" {
		http.Redirect(w, r, "/login?error=invalid_state", http.StatusFound)
		return
	}

	token, err := h.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		slog.Error("OIDC code exchange failed", "error", err)
		http.Redirect(w, r, "/login?error=exchange_failed", http.StatusFound)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Redirect(w, r, "/login?error=no_id_token", http.StatusFound)
		return
	}

	idToken, err := h.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		slog.Error("OIDC token verification failed", "error", err)
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
		h.handleLink(w, r, sess, h.providerSlug, claims.Sub, claims.Email, claims.EmailVerified)
		return
	}

	h.handleLogin(w, r, sess, h.providerSlug, claims.Sub, claims.Email, claims.EmailVerified)
}

func (h *OIDCHandler) handleLogin(w http.ResponseWriter, r *http.Request, sess *session.Session, provider, subject, email string, emailVerified bool) {
	ctx := r.Context()

	// 1. Look up by OIDC account (provider + subject is the canonical identity).
	account, err := service.FindOIDCAccount(ctx, h.Pool, provider, subject)
	if err == nil && account != nil {
		newSess, _ := h.SessionStore.Regenerate(r, sess)
		session.SetSession(r, newSess)
		newSess.SetUserID(account.UserID)
		newSess.Set("auth_method", "oidc")
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// 2. Look up by email → auto-link existing account.
	//
	// SECURITY: only follow this path if the IdP asserts email_verified=true.
	// Otherwise an attacker can register at the IdP with a victim's email
	// address (without proving they own it), click "Sign in with OIDC" on
	// schautrack, and we'd silently link their attacker-controlled OIDC
	// identity to the victim's account.
	if email != "" && emailVerified {
		var userID int
		err := h.Pool.QueryRow(ctx, "SELECT id FROM users WHERE email = $1", email).Scan(&userID)
		if err == nil {
			if err := service.CreateOIDCAccount(ctx, h.Pool, userID, provider, subject, email); err != nil {
				slog.Error("OIDC auto-link failed", "email", email, "error", err)
				http.Redirect(w, r, "/login?error=link_failed", http.StatusFound)
				return
			}
			newSess2, _ := h.SessionStore.Regenerate(r, sess)
			session.SetSession(r, newSess2)
			newSess2.SetUserID(userID)
			newSess2.Set("auth_method", "oidc")
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
	} else if email != "" && !emailVerified {
		slog.Warn("OIDC: skipping email-based auto-link because email_verified=false",
			"provider", provider, "subject", subject, "email", email)
	}

	// 3. Auto-create new user.
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
	clientTz := middleware.GetClientTimezone(r)
	var tzArg any
	if clientTz != "" {
		tzArg = clientTz
	}
	// Mirror the IdP's email_verified flag — if the IdP doesn't trust the
	// email yet, neither do we. The next login attempt with a verified email
	// can complete normal verification.
	err = tx.QueryRow(ctx,
		`INSERT INTO users (email, email_verified, macros_enabled, timezone) VALUES ($1, $2, $3, $4) RETURNING id`,
		email, emailVerified, defaultMacros, tzArg).Scan(&userID)
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

	service.WriteAudit(ctx, h.Pool, h.Cfg.TrustProxy, &userID, service.AuditOIDCAutoCreated, r,
		map[string]any{"provider": provider, "subject": subject, "email": email, "email_verified": emailVerified})

	newSess3, _ := h.SessionStore.Regenerate(r, sess)
	session.SetSession(r, newSess3)
	newSess3.SetUserID(userID)
	newSess3.Set("auth_method", "oidc")
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func (h *OIDCHandler) handleLink(w http.ResponseWriter, r *http.Request, sess *session.Session, provider, subject, email string, emailVerified bool) {
	user := middleware.GetCurrentUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Reject linking an OIDC identity whose email isn't verified at the IdP.
	// Linking is the user's explicit action, but we still don't want them
	// associating an unproven email with their account — and if the IdP
	// later verifies a different email for the same subject, our local
	// records would silently disagree with reality.
	if email == "" || !emailVerified {
		slog.Warn("OIDC link rejected: email missing or unverified",
			"provider", provider, "subject", subject,
			"email", email, "verified", emailVerified)
		http.Redirect(w, r, "/settings?error=oidc_email_unverified", http.StatusFound)
		return
	}

	// Check if already linked by another user.
	existing, err := service.FindOIDCAccount(r.Context(), h.Pool, provider, subject)
	if err == nil && existing != nil && existing.UserID != user.ID {
		http.Redirect(w, r, "/settings?error=oidc_already_linked", http.StatusFound)
		return
	}

	if err := service.CreateOIDCAccount(r.Context(), h.Pool, user.ID, provider, subject, email); err != nil {
		slog.Error("OIDC link failed", "user_id", user.ID, "error", err)
		http.Redirect(w, r, "/settings?error=oidc_link_failed", http.StatusFound)
		return
	}
	service.WriteAudit(r.Context(), h.Pool, h.Cfg.TrustProxy, &user.ID, service.AuditOIDCLinked, r,
		map[string]any{"provider": provider, "subject": subject, "email": email})
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

	service.WriteAudit(r.Context(), h.Pool, h.Cfg.TrustProxy, &user.ID, service.AuditOIDCUnlinked, r,
		map[string]any{"oidc_account_id": body.ID})
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
	// RawURLEncoding drops '=' padding — the value goes into a URL query
	// parameter and into the session, both of which are happier without it.
	return base64.RawURLEncoding.EncodeToString(b), nil
}
