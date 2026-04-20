package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	DatabaseURL string
	SessionSecret string
	Port        string
	AdminEmail  string
	BuildVersion string

	// SEO
	RobotsIndex bool
	BaseURL     string

	// Legal
	ImprintURL     string
	ImprintAddress string
	ImprintEmail   string
	SupportEmail   string

	// AI
	AIProvider         string
	AIKey              string
	AIKeyEncryptSecret string
	AIEndpoint         string
	AIModel            string
	AIDailyLimit       int

	// Features
	EnableBarcode      bool
	EnableRegistration string

	// Rate limiting
	RateLimitAuth   int
	RateLimitStrict int
	TrustProxy      bool

	// SMTP
	SMTPHost   string
	SMTPPort   int
	SMTPUser   string
	SMTPPass   string
	SMTPFrom   string
	SMTPSecure bool

	// OIDC (single provider)
	OIDC              *OIDCConfig
	OIDCRequireInvite bool
	OIDCRedirectURL   string

	// Passkeys
	PasskeysRPID      string
	PasskeysRPName    string
	PasskeysRPOrigins []string
}

type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Label        string // button text
	Slug         string // stable key for DB + logo lookup (derived from issuer hostname)
	LogoURL      string // "/oidc-logos/<slug>.svg" if slug matches a known brand, else ""
}

func Load() (*Config, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("FATAL: DATABASE_URL environment variable is required")
	}

	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		return nil, fmt.Errorf("FATAL: SESSION_SECRET environment variable is required")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	aiDailyLimit, _ := strconv.Atoi(os.Getenv("AI_DAILY_LIMIT"))

	rateLimitAuth, _ := strconv.Atoi(os.Getenv("RATE_LIMIT_AUTH"))
	if rateLimitAuth == 0 {
		rateLimitAuth = 10
	}

	rateLimitStrict, _ := strconv.Atoi(os.Getenv("RATE_LIMIT_STRICT"))
	if rateLimitStrict == 0 {
		rateLimitStrict = 5
	}

	smtpPort, _ := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if smtpPort == 0 {
		smtpPort = 587
	}

	return &Config{
		DatabaseURL:   dbURL,
		SessionSecret: sessionSecret,
		Port:          port,
		AdminEmail:    os.Getenv("ADMIN_EMAIL"),
		BuildVersion:  envOr("BUILD_VERSION", "dev"),

		RobotsIndex: os.Getenv("ROBOTS_INDEX") == "true",
		BaseURL:     os.Getenv("BASE_URL"),

		ImprintURL:     envOr("IMPRINT_URL", "/imprint"),
		ImprintAddress: os.Getenv("IMPRINT_ADDRESS"),
		ImprintEmail:   os.Getenv("IMPRINT_EMAIL"),
		SupportEmail:   os.Getenv("SUPPORT_EMAIL"),

		AIProvider:         os.Getenv("AI_PROVIDER"),
		AIKey:              os.Getenv("AI_KEY"),
		AIKeyEncryptSecret: os.Getenv("AI_KEY_ENCRYPTION_SECRET"),
		AIEndpoint:         os.Getenv("AI_ENDPOINT"),
		AIModel:            os.Getenv("AI_MODEL"),
		AIDailyLimit:       aiDailyLimit,

		EnableBarcode:      os.Getenv("ENABLE_BARCODE") != "false",
		EnableRegistration: os.Getenv("ENABLE_REGISTRATION"),

		RateLimitAuth:   rateLimitAuth,
		RateLimitStrict: rateLimitStrict,
		TrustProxy:    os.Getenv("TRUST_PROXY") != "false", // default true for k8s/docker

		SMTPHost:   os.Getenv("SMTP_HOST"),
		SMTPPort:   smtpPort,
		SMTPUser:   os.Getenv("SMTP_USER"),
		SMTPPass:   os.Getenv("SMTP_PASS"),
		SMTPFrom:   os.Getenv("SMTP_FROM"),
		SMTPSecure: os.Getenv("SMTP_SECURE") == "true",

		OIDC:              parseOIDCConfig(),
		OIDCRequireInvite: os.Getenv("OIDC_REQUIRE_INVITE") == "true",
		OIDCRedirectURL:   os.Getenv("OIDC_REDIRECT_URL"),

		PasskeysRPID:      os.Getenv("PASSKEYS_RP_ID"),
		PasskeysRPName:    envOr("PASSKEYS_RP_NAME", "Schautrack"),
		PasskeysRPOrigins: parseCSV(os.Getenv("PASSKEYS_RP_ORIGINS")),
	}, nil
}

func (c *Config) IsSmtpConfigured() bool {
	return c.SMTPHost != "" && c.SMTPFrom != ""
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// bundledLogoSlugs names the SVG files shipped under public/oidc-logos/.
// Order matters: matched left-to-right via substring against the issuer URL.
var bundledLogoSlugs = []string{
	"google", "microsoft", "github", "gitlab", "apple",
	"authentik", "keycloak", "authelia", "zitadel",
}

// deriveSlugAndLogo picks a stable slug from the issuer URL.
// If the hostname (or path) contains a known brand, the slug is that brand
// and a bundled SVG URL is returned. Otherwise the slug falls back to the
// hostname and no logo is shown.
func deriveSlugAndLogo(issuer string) (slug, logoURL string) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" {
		return "oidc", ""
	}
	host := strings.ToLower(u.Host)
	// Microsoft's well-known issuer is "login.microsoftonline.com" — map it to the "microsoft" bundle.
	haystack := host + u.Path
	for _, s := range bundledLogoSlugs {
		if strings.Contains(haystack, s) {
			return s, "/oidc-logos/" + s + ".svg"
		}
	}
	return host, ""
}

func parseOIDCConfig() *OIDCConfig {
	issuer := strings.TrimSpace(os.Getenv("OIDC_ISSUER"))
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	if issuer == "" || clientID == "" || clientSecret == "" {
		return nil
	}
	slug, logoURL := deriveSlugAndLogo(issuer)
	label := os.Getenv("OIDC_LABEL")
	if label == "" {
		if slug != "" && slug != "oidc" {
			label = strings.ToUpper(slug[:1]) + slug[1:]
		} else {
			label = "SSO"
		}
	}
	return &OIDCConfig{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Label:        label,
		Slug:         slug,
		LogoURL:      logoURL,
	}
}

func (c *Config) PasskeysEnabled() bool {
	return c.PasskeysRPID != ""
}

func (c *Config) OIDCEnabled() bool {
	return c.OIDC != nil
}
