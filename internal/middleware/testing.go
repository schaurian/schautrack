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

// WithTestAPIToken injects an API token into the context for testing purposes.
// Like WithTestUser, it exists because apiTokenContextKey is unexported: a test
// that wants to exercise a scope decision (GetAPIToken + ScopeSatisfies) would
// otherwise have to mint a real token row and authenticate against a live
// database just to reach the branch it cares about.
func WithTestAPIToken(ctx context.Context, t *model.APIToken) context.Context {
	return context.WithValue(ctx, apiTokenContextKey, t)
}
