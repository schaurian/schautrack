package handler

import (
	"context"
	"strings"

	"schautrack/internal/config"
	"schautrack/internal/database"
)

// Registration modes returned by registrationMode.
const (
	regModeOpen   = "open"   // anyone may register, no invite required
	regModeInvite = "invite" // registration allowed only with a valid invite code
	regModeClosed = "closed" // registration fully disabled
)

// registrationMode normalizes the raw enable_registration setting value into
// one of three canonical modes. It fails safe in the security-sensitive
// direction: only the explicit "false" value disables sign-up, and only the
// explicit "invite" value gates on an invite code. Every other value —
// "" (unset), "open", "true", or anything unrecognised — is treated as open
// registration.
func registrationMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "false":
		return regModeClosed
	case "invite":
		return regModeInvite
	default:
		return regModeOpen
	}
}

// effectiveRegistrationMode resolves the active registration mode from the
// admin settings cache (env var → DB → default), normalised via
// registrationMode. This is the single source of truth used by every code
// path that gates sign-up (credential registration, the registration-info
// endpoint, and OIDC auto-provisioning).
func effectiveRegistrationMode(ctx context.Context, settings *database.SettingsCache, cfg *config.Config) string {
	result := settings.GetEffectiveSetting(ctx, "enable_registration", cfg.EnableRegistration)
	val := ""
	if result.Value != nil {
		val = *result.Value
	}
	return registrationMode(val)
}
