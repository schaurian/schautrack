package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/middleware"
	"schautrack/internal/service"
)

// APITokensHandler manages personal access tokens.
//
// These endpoints live on the SESSION-authenticated surface, not on /api/v1,
// and that separation is deliberate: a token must never be able to mint another
// token. If it could, a single leaked read-only token could be escalated into a
// permanent full-scope one, and revoking the original would not undo it.
// Minting requires a logged-in browser session with fresh primary auth.
type APITokensHandler struct {
	Pool       *pgxpool.Pool
	TrustProxy bool
}

type apiTokenView struct {
	ID         int        `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`

	// Expired is computed here rather than left to the client to derive from
	// ExpiresAt. The browser clock is not the clock the limit is enforced
	// against, and the UI both marks dead rows and gates its "New token"
	// button on this — so it has to be the server's answer (issue #299).
	Expired bool `json:"expired"`
}

// List handles GET /api/tokens.
func (h *APITokensHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	tokens, err := service.ListAPITokens(r.Context(), h.Pool, user.ID)
	if err != nil {
		slog.Error("failed to list api tokens", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Could not load tokens.")
		return
	}

	// One clock reading for the whole list, so two rows expiring in the same
	// instant cannot be classified differently.
	now := time.Now()
	views := make([]apiTokenView, 0, len(tokens))
	for _, t := range tokens {
		views = append(views, apiTokenView{
			ID: t.ID, Name: t.Name, Prefix: t.Prefix, Scopes: t.Scopes,
			ExpiresAt: t.ExpiresAt, LastUsedAt: t.LastUsedAt, CreatedAt: t.CreatedAt,
			Expired: !t.Active(now),
		})
	}

	// The scope catalogue ships with the list so the UI renders the checkbox
	// set from the server's definition instead of a hardcoded copy that can
	// fall out of sync when a scope is added.
	scopes := make([]map[string]string, 0, len(service.ScopeDescriptions))
	for _, s := range service.ScopeDescriptions {
		scopes = append(scopes, map[string]string{"scope": s.Scope, "description": s.Description})
	}

	JSON(w, http.StatusOK, map[string]any{
		"ok": true, "tokens": views, "scopes": scopes,
		"max": service.MaxTokensPerUser,
	})
}

// Create handles POST /api/tokens. The raw token is in the response and is
// never retrievable again.
func (h *APITokensHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresIn *int     `json:"expires_in_days"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	var expiresAt *time.Time
	if body.ExpiresIn != nil {
		if *body.ExpiresIn < 1 || *body.ExpiresIn > 3650 {
			ErrorJSON(w, http.StatusBadRequest, "Expiry must be between 1 and 3650 days.")
			return
		}
		t := time.Now().AddDate(0, 0, *body.ExpiresIn)
		expiresAt = &t
	}

	user := middleware.GetCurrentUser(r)
	token, raw, err := service.CreateAPIToken(r.Context(), h.Pool, user.ID, body.Name, body.Scopes, expiresAt)
	if err != nil {
		if errors.Is(err, service.ErrTokenLimit) {
			ErrorJSON(w, http.StatusConflict, err.Error())
			return
		}
		// ValidateScopes and the name/expiry checks all return plain errors
		// whose text is safe to show — they describe the caller's input.
		if errors.Is(err, service.ErrNoScopes) || isUserInputError(err) {
			ErrorJSON(w, http.StatusBadRequest, err.Error())
			return
		}
		slog.Error("failed to create api token", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Could not create the token.")
		return
	}

	service.WriteAudit(r.Context(), h.Pool, h.TrustProxy, &user.ID, "api_token_created", r,
		map[string]any{"token_id": token.ID, "name": token.Name, "scopes": token.Scopes})

	JSON(w, http.StatusOK, map[string]any{
		"ok": true,
		// The one and only time this value exists outside the caller's hands.
		"token": raw,
		"record": apiTokenView{
			ID: token.ID, Name: token.Name, Prefix: token.Prefix, Scopes: token.Scopes,
			ExpiresAt: token.ExpiresAt, CreatedAt: token.CreatedAt,
		},
	})
}

// Revoke handles POST /api/tokens/{id}/delete.
//
// Deliberately NOT step-up gated. Revocation is the action a user takes when
// they think a token has leaked, and putting a re-authentication prompt between
// them and the kill switch is exactly the wrong tradeoff.
func (h *APITokensHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid token id")
		return
	}
	user := middleware.GetCurrentUser(r)
	ok, err := service.RevokeAPIToken(r.Context(), h.Pool, user.ID, id)
	if err != nil {
		slog.Error("failed to revoke api token", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Could not revoke the token.")
		return
	}
	if !ok {
		ErrorJSON(w, http.StatusNotFound, "Token not found")
		return
	}

	service.WriteAudit(r.Context(), h.Pool, h.TrustProxy, &user.ID, "api_token_revoked", r,
		map[string]any{"token_id": id})

	OkJSON(w)
}

// isUserInputError reports whether err came from validating the caller's
// input (and so is safe to echo) rather than from the database.
func isUserInputError(err error) bool {
	switch err.Error() {
	case "name is required", "expires_at must be in the future":
		return true
	}
	// ValidateScopes formats unknown scopes as: unknown scope "foo"
	return len(err.Error()) > 14 && err.Error()[:14] == "unknown scope "
}
