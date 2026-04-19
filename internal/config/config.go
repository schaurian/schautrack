package config

import (
	"fmt"
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

	// OIDC
	OIDCProviders    []OIDCProvider
	OIDCRequireInvite bool
	OIDCRedirectURL   string

	// Passkeys
	PasskeysRPID      string
	PasskeysRPName    string
	PasskeysRPOrigins []string
}

type OIDCProvider struct {
	Name         string
	ClientID     string
	ClientSecret string
	IssuerURL    string
	Label        string
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

		OIDCProviders:     parseOIDCProviders(),
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

// Well-known OIDC issuers
var wellKnownIssuers = map[string]string{
	"google": "https://accounts.google.com",
}

func parseOIDCProviders() []OIDCProvider {
	names := parseCSV(os.Getenv("OIDC_PROVIDERS"))
	if len(names) == 0 {
		return nil
	}
	providers := make([]OIDCProvider, 0, len(names))
	for _, name := range names {
		upper := strings.ToUpper(name)
		clientID := os.Getenv("OIDC_" + upper + "_CLIENT_ID")
		clientSecret := os.Getenv("OIDC_" + upper + "_CLIENT_SECRET")
		if clientID == "" || clientSecret == "" {
			continue
		}
		issuer := os.Getenv("OIDC_" + upper + "_ISSUER")
		if issuer == "" {
			issuer = wellKnownIssuers[strings.ToLower(name)]
		}
		if issuer == "" {
			continue // no issuer, skip
		}
		label := os.Getenv("OIDC_" + upper + "_LABEL")
		if label == "" {
			label = strings.ToUpper(name[:1]) + name[1:]
		}
		providers = append(providers, OIDCProvider{
			Name:         strings.ToLower(name),
			ClientID:     clientID,
			ClientSecret: clientSecret,
			IssuerURL:    issuer,
			Label:        label,
		})
	}
	return providers
}

func (c *Config) PasskeysEnabled() bool {
	return c.PasskeysRPID != ""
}

func (c *Config) OIDCEnabled() bool {
	return len(c.OIDCProviders) > 0
}

func (c *Config) FindOIDCProvider(name string) *OIDCProvider {
	for i := range c.OIDCProviders {
		if c.OIDCProviders[i].Name == name {
			return &c.OIDCProviders[i]
		}
	}
	return nil
}
