package handler

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"schautrack/internal/database"
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
	Key       string                   // DB key in admin_settings + JSON key
	Env       string                   // matching environment variable name
	Section   string                   // grouping for the UI ("general", "ai", …)
	Tier      string                   // "hot" = takes effect next request; "restart" = needs server restart
	Secret    bool                     // mask the value in the UI; don't include the value in audit logs
	Dangerous bool                     // shows a typed-confirmation dialog before save
	Help      string                   // short help text shown under the field
	Validate  func(value string) error // optional value validator; called server-side on every save
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
		Help:     `One of: openai, claude, gemini, ollama.`,
		Validate: oneOf("openai", "claude", "gemini", "ollama", "")},
	{Key: "ai_key", Env: "AI_KEY", Section: "ai", Tier: "hot", Secret: true,
		Help: "Global API key (fallback when users don't have their own)."},
	{Key: "ai_endpoint", Env: "AI_ENDPOINT", Section: "ai", Tier: "hot",
		Help:     "Custom endpoint override. Leave empty for provider defaults.",
		Validate: validURL},
	{Key: "ai_model", Env: "AI_MODEL", Section: "ai", Tier: "hot",
		Help: `Model name (e.g. gpt-4o, claude-sonnet-4-5-20250929, gemini-3.6-flash, gemma3:12b).`},
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
		Help:     "OIDC issuer URL. Setting this enables OIDC sign-in.",
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
		Help:     "Allowed origins, comma-separated full URLs with scheme. Defaults to https://<rp_id>.",
		Validate: validOriginList},

	// =========================================================================
	// Features
	// =========================================================================
	{Key: "enable_barcode", Env: "ENABLE_BARCODE", Section: "features", Tier: "hot",
		Help:     "Enable barcode scanning via OpenFoodFacts.",
		Validate: validBool},
	{Key: "enable_registration", Env: "ENABLE_REGISTRATION", Section: "features", Tier: "hot",
		Help: `"open" (or "true") allows public sign-up; "invite" requires a valid invite code; "false" fully disables sign-up.`,
		// "true" is accepted as a synonym for "open". Anything unrecognised is
		// treated as open registration (see registrationMode); only "invite"
		// gates on a code and only "false" disables sign-up.
		Validate: oneOf("open", "true", "false", "invite", "")},

	// =========================================================================
	// SMTP
	// =========================================================================
	{Key: "smtp_host", Env: "SMTP_HOST", Section: "smtp", Tier: "restart",
		Help:     "SMTP server hostname.",
		Validate: validHostPort},
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

// adminSettingResponse builds the wire representation of a single setting for
// GET /api/admin (see AdminData).
//
// Secret values never cross the wire back to the UI: the response carries only
// isSet, telling the client that something is stored without revealing it.
// Extracted from the handler so the redaction rule is assertable without a
// database — see TestAdminSettingsTableIsConsistent.
func adminSettingResponse(s *AdminSetting, effective database.SettingResult) map[string]any {
	isSet := effective.Value != nil && *effective.Value != ""
	val := ""
	if isSet && !s.Secret {
		val = *effective.Value
	}
	return map[string]any{
		"value":     val,
		"source":    effective.Source,
		"section":   s.Section,
		"tier":      s.Tier,
		"secret":    s.Secret,
		"dangerous": s.Dangerous,
		"help":      s.Help,
		"isSet":     isSet, // for secret fields: tells the UI "something is stored" without revealing it
		"envVar":    s.Env,
	}
}

// =============================================================================
// validators
// =============================================================================

func validBool(v string) error {
	if v == "" || v == "true" || v == "false" {
		return nil
	}
	return fmt.Errorf("must be true or false")
}

// validURL requires a full http(s) URL.
//
// The scheme allow-list is deliberate: every key this gates (base_url,
// ai_endpoint, oidc_issuer, oidc_redirect_url) is fetched or emitted as a web
// URL. base_url in particular is interpolated into SEO meta tags and used to
// build the OIDC redirect URL, so a "javascript:" or "data:" value stored here
// would end up in a rendered link. url.Parse alone accepts those.
func validURL(v string) error {
	if v == "" {
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return fmt.Errorf("must be a full URL with scheme")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("must be an http:// or https:// URL")
	}
	return nil
}

// validEmail requires a bare address (a@b.com), not the RFC 5322 display-name
// form ("Foo <a@b.com>") that mail.ParseAddress also accepts.
//
// smtp_from is used verbatim both in the From: header and as the SMTP MAIL
// FROM argument (service.EmailService.send → c.Mail(from)); a display-name
// value is legal in the header but not in the envelope, so it would be
// accepted at write time and then fail every send after the restart. The other
// keys this gates (support_email, imprint_email) are rendered as contact
// addresses, where a bare address is likewise what's wanted.
func validEmail(v string) error {
	if v == "" {
		return nil
	}
	addr, err := mail.ParseAddress(v)
	if err != nil {
		return fmt.Errorf("must be a valid email address")
	}
	if addr.Name != "" || addr.Address != v {
		return fmt.Errorf("must be a bare email address (no display name or angle brackets)")
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
// hostnameRe matches a DNS hostname by RFC 1123 label rules: each label is
// 1-63 chars of letters, digits and hyphens, not starting or ending with a
// hyphen. A single label ("localhost") is allowed — self-hosted deployments
// use one — and so is a trailing dot on a fully-qualified name.
//
// Underscores are deliberately excluded. They are legal in some DNS records
// but not in hostnames, and WebAuthn compares the RP ID against the browser's
// origin host, which will never contain one.
var hostnameRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$`)

// validRPID requires a bare hostname.
//
// This was a three-character blocklist — it rejected only "://", "/" and ":"
// — so "not a hostname", "exam_ple.com" and "example.com " (trailing space)
// were all accepted (#348). Getting the RP ID wrong breaks passkey login for
// every user at once, and it is a restart-tier setting, so the failure appears
// at the next boot rather than at the write that caused it. An allow-list is
// the only shape that can catch a value that is merely not a hostname.
//
// The blocklist's own cases still fail, now as a consequence of the grammar
// rather than as three special cases: a scheme, a port or a path all introduce
// characters no label may contain.
func validRPID(v string) error {
	if v == "" {
		return nil
	}
	if len(v) > 253 {
		return fmt.Errorf("must be at most 253 characters")
	}
	if !hostnameRe.MatchString(v) {
		return fmt.Errorf("must be a bare hostname (no scheme, port, path, spaces, or underscores)")
	}
	return nil
}

// validOriginList validates passkeys_rp_origins: a comma-separated list of
// full origins.
//
// It had no validator at all (#350). WebAuthn compares the browser's origin
// against this list byte-for-byte, so a missing scheme or a trailing slash
// does not "mostly work" — it silently matches nothing and every passkey login
// fails. Restart-tier and Dangerous, so the damage lands at the next boot,
// far from the admin who typed it.
func validOriginList(v string) error {
	if v == "" {
		return nil
	}
	for _, raw := range strings.Split(v, ",") {
		o := strings.TrimSpace(raw)
		if o == "" {
			return fmt.Errorf("contains an empty entry — check for a stray comma")
		}
		u, err := url.Parse(o)
		if err != nil || u.Host == "" {
			return fmt.Errorf("%q must be a full origin, e.g. https://app.example.com", o)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%q must use http:// or https://", o)
		}
		// An origin is scheme + host [+ port] and nothing else. A path — even
		// a bare "/" — makes the string unequal to what a browser sends.
		if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("%q must be an origin only: no path, query, or fragment (drop the trailing slash)", o)
		}
	}
	return nil
}

// validHostPort accepts a bare hostname, optionally with a port, for
// smtp_host. It had no validator either (#350); a bad value surfaces as a
// failed send long after the setting was saved.
//
// A port is tolerated here rather than rejected: smtp_port exists, but
// "smtp.example.com:587" is what people paste, and splitting it is friendlier
// than refusing it outright would be. IPv6 literals must be bracketed, which
// is what net.SplitHostPort expects anyway.
func validHostPort(v string) error {
	if v == "" {
		return nil
	}
	host := v
	if h, _, err := net.SplitHostPort(v); err == nil {
		host = h
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		if ip := net.ParseIP(host[1 : len(host)-1]); ip != nil {
			return nil
		}
		return fmt.Errorf("%q is not a valid IPv6 literal", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil
	}
	return validRPID(host)
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
