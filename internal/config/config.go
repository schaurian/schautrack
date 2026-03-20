package config

import (
	"fmt"
	"os"
	"strconv"
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
	EnableBarcode    bool
	RegistrationMode string

	// SMTP
	SMTPHost   string
	SMTPPort   int
	SMTPUser   string
	SMTPPass   string
	SMTPFrom   string
	SMTPSecure bool
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

		EnableBarcode:    os.Getenv("ENABLE_BARCODE") != "false",
		RegistrationMode: os.Getenv("REGISTRATION_MODE"),

		SMTPHost:   os.Getenv("SMTP_HOST"),
		SMTPPort:   smtpPort,
		SMTPUser:   os.Getenv("SMTP_USER"),
		SMTPPass:   os.Getenv("SMTP_PASS"),
		SMTPFrom:   os.Getenv("SMTP_FROM"),
		SMTPSecure: os.Getenv("SMTP_SECURE") == "true",
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
