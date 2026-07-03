package handler

import (
	"strings"
	"testing"

	"schautrack/internal/session"
)

func TestRecordLogin2FAFailure_LockoutOnFifthFailure(t *testing.T) {
	sess := &session.Session{ID: "t", Data: make(map[string]any)}
	sess.Set("pendingUserId", 42)

	for i := 1; i < maxLogin2FAFailures; i++ {
		if locked := recordLogin2FAFailure(sess); locked {
			t.Fatalf("locked out after %d failures, want lockout only at %d", i, maxLogin2FAFailures)
		}
		if got, _ := sess.GetInt("login2faFailures"); got != i {
			t.Errorf("failure counter = %d after %d failures", got, i)
		}
		if _, ok := sess.GetInt("pendingUserId"); !ok {
			t.Fatalf("pendingUserId dropped after only %d failures", i)
		}
	}

	if locked := recordLogin2FAFailure(sess); !locked {
		t.Fatalf("no lockout on failure #%d", maxLogin2FAFailures)
	}
	if _, ok := sess.GetInt("pendingUserId"); ok {
		t.Error("pendingUserId must be cleared on lockout")
	}
	if _, ok := sess.GetInt("login2faFailures"); ok {
		t.Error("failure counter must be cleared on lockout")
	}
}

func TestEqualizeLoginTiming_UsesValidArgon2Hash(t *testing.T) {
	hash := dummyPasswordHash()
	if hash == "" {
		t.Fatal("dummy password hash is empty")
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("dummy hash is not argon2id: %q", hash)
	}
	// The dummy hash must never verify an attacker-supplied password.
	valid, err := verifyPassword(hash, "any-password-at-all")
	if err != nil {
		t.Fatalf("verifyPassword on dummy hash: %v", err)
	}
	if valid {
		t.Error("dummy hash verified an arbitrary password")
	}
	// And the equalization call itself must be safe to invoke.
	equalizeLoginTiming("some-password")
	equalizeLoginTiming("")
}
