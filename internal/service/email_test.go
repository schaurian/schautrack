package service

import (
	"net"
	"testing"

	"schautrack/internal/config"
)

// closedPortConfig returns an SMTP config pointing at a local port that is
// guaranteed to be closed (we bind it, learn the number, then release it), so
// SendEmail fails fast with a connection error and no network dependency.
func closedPortConfig(t *testing.T) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return &config.Config{
		SMTPHost: "127.0.0.1",
		SMTPPort: port,
		SMTPFrom: "noreply@example.com",
	}
}

func TestSendEmail_NotConfiguredReturnsError(t *testing.T) {
	es := NewEmailService(&config.Config{})
	if err := es.SendEmail("to@example.com", "subject", "text", ""); err == nil {
		t.Error("SendEmail with unconfigured SMTP returned nil, want error")
	}
}

func TestSendEmail_SMTPFailureReturnsError(t *testing.T) {
	es := NewEmailService(closedPortConfig(t))
	err := es.SendEmail("to@example.com", "subject", "text body", "<p>html</p>")
	if err == nil {
		t.Fatal("SendEmail against a closed SMTP port returned nil, want error")
	}
}

func TestEmailWrappers_PropagateSendErrors(t *testing.T) {
	es := NewEmailService(closedPortConfig(t))

	if err := es.SendVerificationEmail("to@example.com", "123456"); err == nil {
		t.Error("SendVerificationEmail returned nil on SMTP failure, want error")
	}
	if err := es.SendPasswordResetEmail("to@example.com", "123456"); err == nil {
		t.Error("SendPasswordResetEmail returned nil on SMTP failure, want error")
	}
	if err := es.Send2FAResetEmail("to@example.com", "123456"); err == nil {
		t.Error("Send2FAResetEmail returned nil on SMTP failure, want error")
	}
	if err := es.SendEmailChangeVerification("to@example.com", "123456"); err == nil {
		t.Error("SendEmailChangeVerification returned nil on SMTP failure, want error")
	}
}
