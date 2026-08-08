package handler

import (
	"strings"
	"testing"
)

// TestMigrationRefusesWhatBcryptDidNotValidate pins #397.
//
// bcrypt reads 72 bytes; argon2id reads all of them. Migrating the submitted
// string after a bcrypt login therefore narrows the account to one member of
// the set that used to work, picked by whoever logged in last — including
// someone who only ever had the 72-byte prefix.
func TestMigrationRefusesWhatBcryptDidNotValidate(t *testing.T) {
	if bcryptMaxBytes != 72 {
		t.Fatalf("bcryptMaxBytes = %d, want 72 — this is a property of bcrypt's key schedule, not a tunable",
			bcryptMaxBytes)
	}

	// A nil pool would panic if the guard let execution through, which is the
	// assertion: the length check must return before touching the database.
	long := strings.Repeat("a", bcryptMaxBytes+1)
	migratePasswordHash(nil, 1, long)

	// Exactly at the bound is fine to migrate — bcrypt saw all of it — but with
	// a nil pool we can only assert it gets far enough to try, so that case is
	// covered by the handler tests instead.
}

// TestBackupCodeLengthGuard pins #404: the client string is bounded before it
// reaches a hash loop that runs once per stored code.
func TestBackupCodeLengthGuard(t *testing.T) {
	if maxBackupCodeBytes < 8 {
		t.Fatalf("maxBackupCodeBytes = %d, below the 8 digits a real code has", maxBackupCodeBytes)
	}
	if maxBackupCodeBytes > 256 {
		t.Errorf("maxBackupCodeBytes = %d is too loose to bound the per-code SHA-256 work", maxBackupCodeBytes)
	}
	// A nil pool would panic if the guard let execution through.
	if verifyAndMarkBackupCode(nil, nil, 1, strings.Repeat("9", maxBackupCodeBytes+1)) {
		t.Error("an over-long backup code was accepted")
	}
}
