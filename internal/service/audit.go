package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"schautrack/internal/clientip"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Audit action codes — stable short identifiers, not human strings. Use these
// constants everywhere so we can grep / aggregate without typos.
const (
	AuditLogin                = "login"
	AuditLoginFailed          = "login_failed"
	AuditLogout               = "logout"
	AuditPasswordChanged      = "password_changed"
	AuditEmailChangeRequested = "email_change_requested"
	AuditEmailChanged         = "email_changed"
	AuditTOTPEnabled          = "totp_enabled"
	AuditTOTPDisabled         = "totp_disabled"
	AuditTOTPReset            = "totp_reset"
	AuditBackupCodesRegen     = "backup_codes_regenerated"
	AuditPasskeyAdded         = "passkey_added"
	AuditPasskeyDeleted       = "passkey_deleted"
	AuditPasskeyRenamed       = "passkey_renamed"
	AuditOIDCLinked           = "oidc_linked"
	AuditOIDCUnlinked         = "oidc_unlinked"
	AuditOIDCAutoCreated      = "oidc_auto_created"
	AuditAccountDeleted       = "account_deleted"
	AuditStepUpSuccess        = "step_up_success"
	AuditStepUpFailed         = "step_up_failed"
	AuditStepUpLockout        = "step_up_lockout"
	AuditAdminSettingChanged  = "admin_setting_changed"
)

// WriteAudit records a sensitive action against the user. Fire-and-forget:
// we never fail the original request just because the audit row didn't write.
//
// userID is nullable so we can record events that happen before the session
// is fully attached (failed login, OIDC sign-in errors). Pass nil if unknown.
//
// metadata is freeform context (e.g. {"old_email": "...", "new_email": "..."}).
// Pass nil for events that don't need extra detail.
func WriteAudit(ctx context.Context, pool *pgxpool.Pool, trustProxy bool,
	userID *int, action string, r *http.Request, metadata map[string]any,
) {
	var ip, ua string
	if r != nil {
		ip = clientIPFromRequest(r, trustProxy)
		ua = r.UserAgent()
		if len(ua) > 512 {
			ua = ua[:512]
		}
	}
	var metaJSON []byte
	if metadata != nil {
		b, err := json.Marshal(metadata)
		if err == nil {
			metaJSON = b
		}
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO audit_log (user_id, action, ip, user_agent, metadata) VALUES ($1, $2, $3, $4, $5)`,
		userID, action, ip, ua, metaJSON,
	); err != nil {
		slog.Warn("audit log write failed", "action", action, "error", err)
	}
}

// clientIPFromRequest delegates to the shared clientip package so the audit
// log and the rate limiter record the same, non-spoofable client IP. It lives
// in its own leaf package (not middleware) to avoid a service → middleware
// import cycle.
func clientIPFromRequest(r *http.Request, trustProxy bool) string {
	return clientip.FromRequest(r, trustProxy)
}
