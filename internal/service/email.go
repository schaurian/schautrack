package service

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"schautrack/internal/config"
)

// SMTP timeouts bound the whole send so a hung or slow mail server can never
// block the synchronous auth handlers (registration / password-reset / 2FA-reset)
// that call SendEmail. Declared as vars so tests can shrink them.
var (
	smtpDialTimeout = 10 * time.Second
	smtpDeadline    = 30 * time.Second
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

	if err := es.send(from, to, []byte(msg)); err != nil {
		// Log the raw SMTP detail server-side only; callers must surface a
		// generic message. Swallowing the error here made every caller
		// report success even when nothing was sent — combined with the
		// unverified-user cleanup that silently cost accounts.
		log.Printf("SMTP send failed: %v", err)
		return fmt.Errorf("email send failed: %w", err)
	}
	return nil
}

// send delivers a single message with a bounded timeout and TLS handling driven
// by the existing SMTP config contract:
//
//   - SMTPSecure=true  → implicit TLS from the first byte (SMTPS, typically :465).
//   - SMTPSecure=false → STARTTLS on a plaintext connection (typically :587).
//     STARTTLS is opportunistic for credential-less dev servers (MailPit, which
//     advertises neither STARTTLS nor AUTH) but *mandatory* whenever credentials
//     are configured, so codes/credentials are never sent over an unencrypted
//     link just because the server failed to advertise STARTTLS.
//
// It mirrors smtp.SendMail but adds a dial + full-exchange deadline; the stdlib
// helper has neither, so a stalled server would wedge the calling auth handler.
func (es *EmailService) send(from, to string, msg []byte) error {
	host := es.cfg.SMTPHost
	addr := net.JoinHostPort(host, strconv.Itoa(es.cfg.SMTPPort))

	// Only use auth when SMTP credentials are provided (e.g., MailPit doesn't support AUTH)
	var auth smtp.Auth
	if es.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", es.cfg.SMTPUser, es.cfg.SMTPPass, host)
	}

	dialer := &net.Dialer{Timeout: smtpDialTimeout}

	var conn net.Conn
	var err error
	if es.cfg.SMTPSecure {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: host})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	// Bound the whole SMTP exchange (greeting, EHLO, TLS, auth, data) so a
	// stalled server cannot block the caller indefinitely.
	if err := conn.SetDeadline(time.Now().Add(smtpDeadline)); err != nil {
		return err
	}

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()

	if !es.cfg.SMTPSecure {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
				return err
			}
		} else if auth != nil {
			return fmt.Errorf("SMTP server %s does not advertise STARTTLS; refusing to send credentials over an unencrypted connection", host)
		}
	}

	if auth != nil {
		if ok, _ := c.Extension("AUTH"); !ok {
			return fmt.Errorf("SMTP server %s does not support AUTH", host)
		}
		if err := c.Auth(auth); err != nil {
			return err
		}
	}

	if err := c.Mail(from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
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
