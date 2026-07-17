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
