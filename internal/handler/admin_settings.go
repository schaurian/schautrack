package handler

import (
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AdminSetting describes one setting that's tunable from /admin.
//
// Single source of truth — the GET /api/admin endpoint, the POST
// /admin/settings handler, and the frontend Admin page all read from this
// list (keyed by Key). Adding a new setting here is enough; nothing else
// needs touching unless the value needs to be read at request time
// (then also wire it through SettingsCache.GetEffectiveSetting in the
// relevant handler).
type AdminSetting struct {
	Key      string                  // DB key in admin_settings + JSON key
	Env      string                  // matching environment variable name
	Section  string                  // grouping for the UI ("general", "ai", …)
	Tier     string                  // "hot" = takes effect next request; "restart" = needs server restart
	Secret   bool                    // mask the value in the UI; don't include the value in audit logs
	Dangerous bool                   // shows a typed-confirmation dialog before save
	Help     string                  // short help text shown under the field
	Validate func(value string) error // optional value validator; called server-side on every save
}

// adminSettings is the canonical ordered list. Order is the display order
// within each section.
var adminSettings = []AdminSetting{
	// =========================================================================
	// General
	// =========================================================================
	{Key: "support_email", Env: "SUPPORT_EMAIL", Section: "general", Tier: "hot",
		Help:     "Contact email shown on support and error pages.",
		Validate: validEmail},
	{Key: "base_url", Env: "BASE_URL", Section: "general", Tier: "restart",
		Help:     "Canonical base URL for SEO meta tags. Leave empty to auto-detect from request.",
		Validate: validURL},

	// =========================================================================
	// AI Features
	// =========================================================================
	{Key: "ai_provider", Env: "AI_PROVIDER", Section: "ai", Tier: "hot",
		Help: `One of: openai, claude, ollama.`,
		Validate: oneOf("openai", "claude", "ollama", "")},
	{Key: "ai_key", Env: "AI_KEY", Section: "ai", Tier: "hot", Secret: true,
		Help: "Global API key (fallback when users don't have their own)."},
	{Key: "ai_endpoint", Env: "AI_ENDPOINT", Section: "ai", Tier: "hot",
		Help:     "Custom endpoint override. Leave empty for provider defaults.",
		Validate: validURL},
	{Key: "ai_model", Env: "AI_MODEL", Section: "ai", Tier: "hot",
		Help: `Model name (e.g. gpt-4o, claude-sonnet-4-5-20250929, gemma3:12b).`},
	{Key: "ai_daily_limit", Env: "AI_DAILY_LIMIT", Section: "ai", Tier: "hot",
		Help:     "Daily AI request limit per user when using the global key. 0 = unlimited.",
		Validate: validNonNegInt},
	{Key: "ai_key_encryption_secret", Env: "AI_KEY_ENCRYPTION_SECRET",
		Section: "ai", Tier: "restart", Secret: true, Dangerous: true,
		Help: "Encrypts user-stored AI keys at rest. Changing this orphans every existing user-saved key — they'll need to re-enter."},

	// =========================================================================
	// OIDC / SSO
	// =========================================================================
	{Key: "oidc_issuer", Env: "OIDC_ISSUER", Section: "oidc", Tier: "restart",
		Help: "OIDC issuer URL. Setting this enables OIDC sign-in.",
		Validate: validURL},
	{Key: "oidc_client_id", Env: "OIDC_CLIENT_ID", Section: "oidc", Tier: "restart",
		Help: "OAuth2 client ID from your provider."},
	{Key: "oidc_client_secret", Env: "OIDC_CLIENT_SECRET", Section: "oidc", Tier: "restart", Secret: true,
		Help: "OAuth2 client secret."},
	{Key: "oidc_label", Env: "OIDC_LABEL", Section: "oidc", Tier: "restart",
		Help: "Button label override (default: derived from issuer host)."},
	{Key: "oidc_require_invite", Env: "OIDC_REQUIRE_INVITE", Section: "oidc", Tier: "restart",
		Help:     "Require an invite code for OIDC sign-up too. Default: OIDC bypasses invite-only.",
		Validate: validBool},
	{Key: "oidc_redirect_url", Env: "OIDC_REDIRECT_URL", Section: "oidc", Tier: "restart",
		Help:     "Callback URL override. Leave empty to auto-build from base URL.",
		Validate: validURL},

	// =========================================================================
	// Passkeys
	// =========================================================================
	{Key: "passkeys_rp_id", Env: "PASSKEYS_RP_ID", Section: "passkeys", Tier: "restart", Dangerous: true,
		Help:     "Relying Party ID — your domain only (no scheme, no port). Changing this invalidates every existing passkey.",
		Validate: validRPID},
	{Key: "passkeys_rp_name", Env: "PASSKEYS_RP_NAME", Section: "passkeys", Tier: "restart",
		Help: "Display name shown in passkey prompts (default: Schautrack)."},
	{Key: "passkeys_rp_origins", Env: "PASSKEYS_RP_ORIGINS", Section: "passkeys", Tier: "restart", Dangerous: true,
		Help: "Allowed origins, comma-separated full URLs with scheme. Defaults to https://<rp_id>."},

	// =========================================================================
	// Features
	// =========================================================================
	{Key: "enable_barcode", Env: "ENABLE_BARCODE", Section: "features", Tier: "hot",
		Help:     "Enable barcode scanning via OpenFoodFacts.",
		Validate: validBool},
	{Key: "enable_registration", Env: "ENABLE_REGISTRATION", Section: "features", Tier: "hot",
		Help:     `"open" (anyone can register) or "false"/"invite" (requires invite code).`,
		Validate: oneOf("open", "false", "invite", "")},

	// =========================================================================
	// SMTP
	// =========================================================================
	{Key: "smtp_host", Env: "SMTP_HOST", Section: "smtp", Tier: "restart",
		Help: "SMTP server hostname."},
	{Key: "smtp_port", Env: "SMTP_PORT", Section: "smtp", Tier: "restart",
		Help:     "SMTP server port (default: 587).",
		Validate: validPort},
	{Key: "smtp_user", Env: "SMTP_USER", Section: "smtp", Tier: "restart", Secret: true,
		Help: "SMTP username."},
	{Key: "smtp_pass", Env: "SMTP_PASS", Section: "smtp", Tier: "restart", Secret: true,
		Help: "SMTP password."},
	{Key: "smtp_from", Env: "SMTP_FROM", Section: "smtp", Tier: "restart",
		Help:     "From address for outgoing email. Defaults to support email if unset.",
		Validate: validEmail},
	{Key: "smtp_secure", Env: "SMTP_SECURE", Section: "smtp", Tier: "restart",
		Help:     `Use TLS from the start (true) or upgrade via STARTTLS (false).`,
		Validate: validBool},

	// =========================================================================
	// Security
	// =========================================================================
	{Key: "step_up_ttl", Env: "STEP_UP_TTL", Section: "security", Tier: "restart",
		Help:     "Step-up auth grace window. Any time.ParseDuration value (e.g. 5m, 30m, 1h). Default: 30m.",
		Validate: validDuration},
	{Key: "rate_limit_auth", Env: "RATE_LIMIT_AUTH", Section: "security", Tier: "restart",
		Help:     "Max authentication attempts per minute per IP (default: 10).",
		Validate: validPositiveInt},
	{Key: "trust_proxy", Env: "TRUST_PROXY", Section: "security", Tier: "restart",
		Help:     "Trust X-Forwarded-For headers. Set false for direct-access deployments without a reverse proxy.",
		Validate: validBool},

	// =========================================================================
	// Legal
	// =========================================================================
	{Key: "enable_legal", Env: "ENABLE_LEGAL", Section: "legal", Tier: "hot",
		Help:     "Enable /imprint, /privacy, /terms pages.",
		Validate: validBool},
	{Key: "imprint_url", Env: "IMPRINT_URL", Section: "legal", Tier: "hot",
		Help: "URL for the imprint link (default: /imprint)."},
	{Key: "imprint_address", Env: "IMPRINT_ADDRESS", Section: "legal", Tier: "hot",
		Help: "Full name and address. Use \\n for line breaks. Rendered as SVG for spam protection."},
	{Key: "imprint_email", Env: "IMPRINT_EMAIL", Section: "legal", Tier: "hot",
		Help:     "Imprint contact email. Rendered as SVG.",
		Validate: validEmail},

	// =========================================================================
	// SEO / Deployment
	// =========================================================================
	{Key: "robots_index", Env: "ROBOTS_INDEX", Section: "seo", Tier: "restart",
		Help:     "Allow search engine indexing. Default: noindex (for self-hosters).",
		Validate: validBool},
}

// adminSettingByKey is a lookup index built from adminSettings.
var adminSettingByKey = func() map[string]*AdminSetting {
	m := make(map[string]*AdminSetting, len(adminSettings))
	for i := range adminSettings {
		m[adminSettings[i].Key] = &adminSettings[i]
	}
	return m
}()

// =============================================================================
// validators
// =============================================================================

func validBool(v string) error {
	if v == "" || v == "true" || v == "false" {
		return nil
	}
	return fmt.Errorf("must be true or false")
}

func validURL(v string) error {
	if v == "" {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("must be a full URL with scheme")
	}
	return nil
}

func validEmail(v string) error {
	if v == "" {
		return nil
	}
	_, err := mail.ParseAddress(v)
	if err != nil {
		return fmt.Errorf("must be a valid email address")
	}
	return nil
}

func validNonNegInt(v string) error {
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fmt.Errorf("must be a non-negative integer")
	}
	return nil
}

func validPositiveInt(v string) error {
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return fmt.Errorf("must be a positive integer")
	}
	return nil
}

func validPort(v string) error {
	if v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("must be a port number 1–65535")
	}
	return nil
}

func validDuration(v string) error {
	if v == "" {
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fmt.Errorf("must be a duration like 5m, 30m, 1h")
	}
	return nil
}

// validRPID rejects values that contain a scheme, port, or path — the WebAuthn
// RP ID is just the hostname.
func validRPID(v string) error {
	if v == "" {
		return nil
	}
	if strings.Contains(v, "://") || strings.Contains(v, "/") || strings.Contains(v, ":") {
		return fmt.Errorf("must be a hostname only (no scheme, port, or path)")
	}
	return nil
}

func oneOf(allowed ...string) func(string) error {
	return func(v string) error {
		for _, a := range allowed {
			if v == a {
				return nil
			}
		}
		return fmt.Errorf("must be one of: %s", strings.Join(allowed, ", "))
	}
}
