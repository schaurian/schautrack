package service

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/smtp"
	"strings"

	"schautrack/internal/config"
)

type EmailService struct {
	cfg *config.Config
}

func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{cfg: cfg}
}

func (es *EmailService) IsConfigured() bool {
	return es.cfg.IsSmtpConfigured()
}

func (es *EmailService) SendEmail(to, subject, text, html string) error {
	if !es.IsConfigured() {
		return fmt.Errorf("SMTP not configured")
	}

	from := es.cfg.SMTPFrom
	msg := buildMimeMessage(from, to, subject, text, html)

	addr := fmt.Sprintf("%s:%d", es.cfg.SMTPHost, es.cfg.SMTPPort)
	auth := smtp.PlainAuth("", es.cfg.SMTPUser, es.cfg.SMTPPass, es.cfg.SMTPHost)

	err := smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
	if err != nil {
		log.Printf("SMTP send failed: %v", err)
		return nil // Don't expose SMTP errors to users
	}
	return nil
}

func (es *EmailService) SendVerificationEmail(email, code string) error {
	subject := "Verify Your Email - Schautrack"
	text := fmt.Sprintf("Your verification code is: %s\n\nThis code expires in 30 minutes.\n\nIf you did not create this account, you can ignore this email.", code)
	html := fmt.Sprintf(`<p>Your verification code is:</p><h2 style="font-family: monospace; letter-spacing: 4px;">%s</h2><p>This code expires in 30 minutes.</p><p>If you did not create this account, you can ignore this email.</p>`, code)
	return es.SendEmail(email, subject, text, html)
}

func (es *EmailService) SendEmailChangeVerification(email, code string) error {
	subject := "Verify Your New Email - Schautrack"
	text := fmt.Sprintf("Your verification code to confirm your new email address is: %s\n\nThis code expires in 30 minutes.\n\nIf you did not request this email change, you can ignore this email.", code)
	html := fmt.Sprintf(`<p>Your verification code to confirm your new email address is:</p><h2 style="font-family: monospace; letter-spacing: 4px;">%s</h2><p>This code expires in 30 minutes.</p><p>If you did not request this email change, you can ignore this email.</p>`, code)
	return es.SendEmail(email, subject, text, html)
}

func (es *EmailService) SendPasswordResetEmail(email, code string) error {
	subject := "Password Reset Code - Schautrack"
	text := fmt.Sprintf("Your password reset code is: %s\n\nThis code expires in 30 minutes.", code)
	html := fmt.Sprintf(`<p>Your password reset code is:</p><h2 style="font-family: monospace; letter-spacing: 4px;">%s</h2><p>This code expires in 30 minutes.</p>`, code)
	return es.SendEmail(email, subject, text, html)
}

func (es *EmailService) Send2FAResetEmail(email, code string) error {
	subject := "2FA Reset Code - Schautrack"
	text := fmt.Sprintf("Your 2FA reset code is: %s\n\nThis code expires in 15 minutes.\n\nIf you did not request this, someone may have your password. Please change it immediately.", code)
	html := fmt.Sprintf(`<p>Your 2FA reset code is:</p><h2 style="font-family: monospace; letter-spacing: 4px;">%s</h2><p>This code expires in 15 minutes.</p><p>If you did not request this, someone may have your password. Please change it immediately.</p>`, code)
	return es.SendEmail(email, subject, text, html)
}

// GenerateResetCode returns a random 6-digit code.
func GenerateResetCode() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	return fmt.Sprintf("%06d", n.Int64()+100000)
}

func buildMimeMessage(from, to, subject, text, html string) string {
	boundary := "----=_Part_" + generateBoundary()
	var sb strings.Builder

	sb.WriteString("From: " + from + "\r\n")
	sb.WriteString("To: " + to + "\r\n")
	sb.WriteString("Subject: " + subject + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n")
	sb.WriteString("\r\n")

	// Text part
	sb.WriteString("--" + boundary + "\r\n")
	sb.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(text + "\r\n")

	// HTML part
	if html != "" {
		sb.WriteString("--" + boundary + "\r\n")
		sb.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		sb.WriteString("\r\n")
		sb.WriteString(html + "\r\n")
	}

	sb.WriteString("--" + boundary + "--\r\n")
	return sb.String()
}

func generateBoundary() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
