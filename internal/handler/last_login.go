package handler

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// recordLogin stamps users.last_login_at for a completed sign-in. It is called
// once on every path that hands a user a NEW authenticated session (password,
// password + 2FA, passkey, OIDC, the auto-login after registration or email
// verification) — right next to the SetUserID that creates that session.
// TestEveryLoginPathRecordsLastLogin fails the build if a SetUserID site
// forgets it.
//
// What deliberately does NOT count as a login: an existing session being
// loaded or extended on later requests (that would be "last active", and would
// mean a write on every request), a correct password that still awaits its
// 2FA code or email verification, and any failed attempt.
//
// Best-effort, like the audit log: the value only feeds the admin user list,
// so a failed write is logged and the sign-in still succeeds.
func recordLogin(ctx context.Context, pool *pgxpool.Pool, userID int) {
	if _, err := pool.Exec(ctx, `UPDATE users SET last_login_at = NOW() WHERE id = $1`, userID); err != nil {
		slog.Warn("failed to record last login", "user_id", userID, "error", err)
	}
}
