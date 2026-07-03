package handler

import (
	"context"

	"github.com/jackc/pgx/v5/pgconn"
)

// sqlExecutor is the subset of pgxpool.Pool / pgx.Tx needed by helpers that
// must run either standalone or inside a transaction.
type sqlExecutor interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// invalidateUserSessions deletes every session row belonging to userID except
// keepSID (the session the user is acting from). Pass keepSID == "" to delete
// ALL of the user's sessions — used by anonymous flows (email password reset,
// 2FA reset) where the actor isn't logged in on the affected account.
//
// Called after credential changes (password reset/change, 2FA disable/reset)
// so an attacker holding a stolen session cookie loses access the moment the
// victim rotates their credentials. Same SQL shape as admin.go's DeleteUser.
func invalidateUserSessions(ctx context.Context, db sqlExecutor, userID int, keepSID string) error {
	if keepSID == "" {
		_, err := db.Exec(ctx,
			`DELETE FROM "session" WHERE (sess::jsonb->>'userId')::int = $1`, userID)
		return err
	}
	_, err := db.Exec(ctx,
		`DELETE FROM "session" WHERE (sess::jsonb->>'userId')::int = $1 AND sid <> $2`, userID, keepSID)
	return err
}
