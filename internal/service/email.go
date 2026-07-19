package service

import (
	"crypto/rand"
	"crypto/tls"
	"embed"
	"fmt"
	htmltemplate "html/template"
	"log"
	"math/big"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	texttemplate "text/template"
	"time"

	"schautrack/internal/config"
)

//go:embed emailtemplates
var emailTemplatesFS embed.FS

// supportedEmailLangs is the allow-list of locales the transactional email
// templates are translated into. Keep in sync with supportedLanguages in
// internal/handler/settings.go and SUPPORTED_LANGUAGES in
// client/src/i18n/index.ts.
var supportedEmailLangs = map[string]bool{
	"en": true, "de": true, "es": true, "fr": true,
	"it": true, "nl": true, "pl": true, "pt": true,
}

// normalizeEmailLang returns a supported locale code for the given raw
// language tag (lowercased, region stripped, e.g. "de-DE" -> "de"). Unknown,
// unsupported, or empty values fall back to "en".
func normalizeEmailLang(lang string) string {
	s := strings.ToLower(strings.TrimSpace(lang))
	if i := strings.IndexAny(s, "-_"); i >= 0 {
		s = s[:i]
	}
	if !supportedEmailLangs[s] {
		return "en"
	}
	return s
}

// renderedEmail holds the rendered subject/text/HTML for a single templated
// email, ready to be handed to EmailService.SendEmail.
type renderedEmail struct {
	Subject string
	Text    string
	HTML    string
}

// renderEmail renders the named email template (e.g. "verification") for the
// given language from internal/service/emailtemplates/<lang>/. lang is
// normalized via normalizeEmailLang, so unsupported/unknown locales silently
// fall back to "en" rather than erroring. An error is returned only when a
// template is missing or genuinely fails to parse/execute.
func renderEmail(name, lang string, data any) (renderedEmail, error) {
	var out renderedEmail
	dir := "emailtemplates/" + normalizeEmailLang(lang) + "/"

	subjectSrc, err := emailTemplatesFS.ReadFile(dir + name + ".subject.tmpl")
	if err != nil {
		return out, fmt.Errorf("read %s subject template: %w", name, err)
	}
	textSrc, err := emailTemplatesFS.ReadFile(dir + name + ".txt.tmpl")
	if err != nil {
		return out, fmt.Errorf("read %s text template: %w", name, err)
	}
	htmlSrc, err := emailTemplatesFS.ReadFile(dir + name + ".html.tmpl")
	if err != nil {
		return out, fmt.Errorf("read %s html template: %w", name, err)
	}

	subjectTmpl, err := texttemplate.New(name + ".subject").Parse(string(subjectSrc))
	if err != nil {
		return out, fmt.Errorf("parse %s subject template: %w", name, err)
	}
	var subjectBuf strings.Builder
	if err := subjectTmpl.Execute(&subjectBuf, data); err != nil {
		return out, fmt.Errorf("execute %s subject template: %w", name, err)
	}

	textTmpl, err := texttemplate.New(name + ".txt").Parse(string(textSrc))
	if err != nil {
		return out, fmt.Errorf("parse %s text template: %w", name, err)
	}
	var textBuf strings.Builder
	if err := textTmpl.Execute(&textBuf, data); err != nil {
		return out, fmt.Errorf("execute %s text template: %w", name, err)
	}

	htmlTmpl, err := htmltemplate.New(name + ".html").Parse(string(htmlSrc))
	if err != nil {
		return out, fmt.Errorf("parse %s html template: %w", name, err)
	}
	var htmlBuf strings.Builder
	if err := htmlTmpl.Execute(&htmlBuf, data); err != nil {
		return out, fmt.Errorf("execute %s html template: %w", name, err)
	}

	out.Subject = strings.TrimRight(subjectBuf.String(), "\n")
	out.Text = strings.TrimRight(textBuf.String(), "\n")
	out.HTML = strings.TrimRight(htmlBuf.String(), "\n")
	return out, nil
}

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

func (es *EmailService) SendVerificationEmail(email, code, lang string) error {
	rendered, err := renderEmail("verification", lang, map[string]any{"Code": code})
	if err != nil {
		return fmt.Errorf("render verification email: %w", err)
	}
	return es.SendEmail(email, rendered.Subject, rendered.Text, rendered.HTML)
}

func (es *EmailService) SendEmailChangeVerification(email, code, lang string) error {
	rendered, err := renderEmail("email_change", lang, map[string]any{"Code": code})
	if err != nil {
		return fmt.Errorf("render email change verification email: %w", err)
	}
	return es.SendEmail(email, rendered.Subject, rendered.Text, rendered.HTML)
}

func (es *EmailService) SendPasswordResetEmail(email, code, lang string) error {
	rendered, err := renderEmail("password_reset", lang, map[string]any{"Code": code})
	if err != nil {
		return fmt.Errorf("render password reset email: %w", err)
	}
	return es.SendEmail(email, rendered.Subject, rendered.Text, rendered.HTML)
}

func (es *EmailService) Send2FAResetEmail(email, code, lang string) error {
	rendered, err := renderEmail("twofa_reset", lang, map[string]any{"Code": code})
	if err != nil {
		return fmt.Errorf("render 2FA reset email: %w", err)
	}
	return es.SendEmail(email, rendered.Subject, rendered.Text, rendered.HTML)
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
