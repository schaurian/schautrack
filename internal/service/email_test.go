package service

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"schautrack/internal/config"
)

// startFakeSMTP starts a minimal in-process SMTP server that runs handle for
// each accepted connection, and returns a config pointing at it. The listener
// is torn down when the test ends.
func startFakeSMTP(t *testing.T, handle func(net.Conn)) *config.Config {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handle(conn)
		}
	}()
	return &config.Config{
		SMTPHost: "127.0.0.1",
		SMTPPort: ln.Addr().(*net.TCPAddr).Port,
		SMTPFrom: "noreply@example.com",
	}
}

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

// A credentialed send against a server that does not advertise STARTTLS must
// fail rather than silently transmit credentials/codes over plaintext.
func TestSendEmail_RequiresStartTLSWhenAuthenticated(t *testing.T) {
	cfg := startFakeSMTP(t, func(conn net.Conn) {
		defer conn.Close()
		br := bufio.NewReader(conn)
		fmt.Fprint(conn, "220 fake ESMTP\r\n")
		if _, err := br.ReadString('\n'); err != nil { // EHLO
			return
		}
		// Advertise neither STARTTLS nor AUTH.
		fmt.Fprint(conn, "250-fake\r\n250 SIZE 10240000\r\n")
		io.Copy(io.Discard, br) // drain until the client hangs up
	})
	cfg.SMTPUser = "user"
	cfg.SMTPPass = "pass"

	es := NewEmailService(cfg)
	err := es.SendEmail("to@example.com", "s", "t", "")
	if err == nil {
		t.Fatal("SendEmail with credentials against a non-TLS server returned nil, want error")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("error = %v, want it to mention refusing to send without STARTTLS", err)
	}
}

// A hung SMTP server (accepts the connection but never speaks) must not block
// the caller indefinitely — the deadline has to fire.
func TestSendEmail_TimesOutOnHungServer(t *testing.T) {
	orig := smtpDeadline
	smtpDeadline = 150 * time.Millisecond
	t.Cleanup(func() { smtpDeadline = orig })

	cfg := startFakeSMTP(t, func(conn net.Conn) {
		defer conn.Close()
		time.Sleep(2 * time.Second) // never send the greeting
	})

	es := NewEmailService(cfg)
	done := make(chan error, 1)
	go func() { done <- es.SendEmail("to@example.com", "s", "t", "") }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("SendEmail against a hung server returned nil, want a timeout error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SendEmail did not return within the deadline; the send is not time-bounded")
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
