package middleware

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/apierr"
	"schautrack/internal/model"
	"schautrack/internal/service"
)

const apiTokenContextKey contextKey = "apiToken"

// GetAPIToken returns the token that authenticated the request, or nil if the
// request was not token-authenticated.
func GetAPIToken(r *http.Request) *model.APIToken {
	t, _ := r.Context().Value(apiTokenContextKey).(*model.APIToken)
	return t
}

// RequireAPIToken authenticates /api/v1 requests from an
// `Authorization: Bearer stk_…` header.
//
// It accepts ONLY bearer tokens. A session cookie is not sufficient here even
// when one is present, and that is the point: cookies are attached by the
// browser automatically, which is exactly what makes CSRF possible. Because
// /api/v1 never treats a cookie as authentication, no request forged by a
// third-party page can carry usable credentials to it, and the whole surface
// needs no CSRF token, no double-submit, and no SameSite reasoning.
//
// The app's own SPA keeps using the cookie session against the legacy routes;
// nothing about this middleware touches that path.
func RequireAPIToken(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Advertise the scheme on every rejection, per RFC 6750 §3.
			raw := service.ParseBearer(r.Header.Get("Authorization"))
			if raw == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="schautrack"`)
				apierr.Write(w, r, apierr.Unauthorized(
					"Provide a personal access token as `Authorization: Bearer stk_…`. "+
						"Session cookies are not accepted on /api/v1."))
				return
			}

			token, err := service.AuthenticateAPIToken(r.Context(), pool, raw)
			if err != nil {
				if !errors.Is(err, service.ErrTokenInvalid) {
					slog.Error("api token lookup failed", "error", err)
					apierr.Write(w, r, apierr.Internal("Could not verify the token."))
					return
				}
				w.Header().Set("WWW-Authenticate",
					`Bearer realm="schautrack", error="invalid_token"`)
				apierr.Write(w, r, apierr.Unauthorized(
					"The token is unknown, revoked, or expired."))
				return
			}

			user, err := GetUserByID(r.Context(), pool, token.UserID)
			if err != nil {
				// The FK is ON DELETE CASCADE, so a live token whose user is
				// gone should be impossible. Treat it as invalid rather than
				// 500 so a mid-deletion race fails closed.
				slog.Error("api token references unloadable user", "error", err, "token_id", token.ID)
				apierr.Write(w, r, apierr.Unauthorized("The token is no longer valid."))
				return
			}

			// Lazily record use. Fire-and-forget on a detached context: the
			// request must not fail, or even wait, because a bookkeeping UPDATE
			// was slow.
			go func(id int) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := service.TouchAPIToken(ctx, pool, id); err != nil {
					slog.Warn("failed to touch api token", "error", err, "token_id", id)
				}
			}(token.ID)

			ctx := context.WithValue(r.Context(), userContextKey, user)
			ctx = context.WithValue(ctx, apiTokenContextKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScope rejects a token that does not carry the given scope.
//
// It must be mounted below RequireAPIToken. A request that reaches it without a
// token is a routing mistake, and it fails closed with 401 rather than assuming
// authorization.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := GetAPIToken(r)
			if token == nil {
				apierr.Write(w, r, apierr.Unauthorized("Authentication required."))
				return
			}
			if !service.ScopeSatisfies(token.Scopes, scope) {
				apierr.Write(w, r, apierr.InsufficientScope(scope))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
