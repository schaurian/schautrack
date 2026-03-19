package session

import "context"

// WithTestSession injects a session into the context for testing purposes.
// This is the only way to set the correct unexported context key from outside the package.
func WithTestSession(ctx context.Context, sess *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, sess)
}
