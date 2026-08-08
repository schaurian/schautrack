package middleware

import (
	"context"

	"schautrack/internal/model"
)

// WithTestUser injects a user into the context for testing purposes.
// It mirrors session.WithTestSession: it is the only way to set the correct
// unexported context key (userContextKey) from outside the package, so that
// handlers calling GetCurrentUser observe an authenticated user without going
// through the full auth middleware and a live database.
func WithTestUser(ctx context.Context, u *model.User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

// WithTestAPIToken injects an authenticated API token into the context, exactly
// as RequireAPIToken would on a successful /api/v1 request.
//
// Same reasoning as WithTestUser: apiTokenContextKey is unexported, so this is
// the only way a test outside this package can drive a token-authenticated
// route — scope checks, per-token and per-user rate limits included — without a
// live database behind the token lookup.
func WithTestAPIToken(ctx context.Context, t *model.APIToken) context.Context {
	return context.WithValue(ctx, apiTokenContextKey, t)
}
