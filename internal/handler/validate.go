package handler

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Sane calendar-year bounds for user-supplied dates. Anything outside is a
// typo or garbage input, not a plausible entry date.
const (
	minDateYear = 1900
	maxDateYear = 2200
)

// Credential bounds shared by every path that creates or changes a user's
// email address or password.
const (
	// MaxEmailBytes is the RFC 5321 maximum reverse-path/forward-path length
	// (64-byte local part + "@" + 255-byte domain). Anything longer cannot be
	// delivered to, and would take an oversized key in the users.email UNIQUE
	// btree index.
	MaxEmailBytes = 320

	// MinPasswordRunes is the minimum password length in *runes*, not bytes.
	// The user-facing message says "characters", so it must count characters:
	// with a byte count, a 4-character CJK passphrase (12 bytes) passed while
	// a 9-character ASCII one did not.
	MinPasswordRunes = 10

	// MaxPasswordBytes caps the password at hashing time. argon2id has no
	// intrinsic length limit, so without a cap a client can make the server
	// Blake2b-hash a multi-megabyte string on every write — a cheap CPU-burn
	// vector. The bound is in bytes because hashing cost is byte-driven.
	MaxPasswordBytes = 1024

	// MaxVerifyPasswordBytes bounds a client-supplied password at the paths
	// that *verify* one rather than set one: login, the 2FA-reset request,
	// and step-up re-authentication (all of which funnel through
	// verifyPassword), plus equalizeLoginTiming on the unknown-email login
	// path.
	//
	// It exists because MaxPasswordBytes deliberately does not apply here.
	// The write validator encodes policy — minimum length, no whitespace-only
	// secrets — and applying policy to a login would lock out any account
	// created before the policy existed. This constant encodes something
	// narrower and non-negotiable: a hard ceiling on how many bytes may reach
	// a password hash function. argon2id's Blake2b pre-hash is linear in
	// input size, so an unbounded string is a free CPU-burn primitive, and on
	// the login endpoint it is reachable *without a valid account* —
	// equalizeLoginTiming hashes whatever was submitted for an email that
	// does not exist. (bcrypt is not affected: Go's blowfish key schedule
	// reads only the first 72 bytes, so a legacy hash costs the same for a
	// 72-byte password and a 5 MB one.)
	//
	// The value is 4x MaxPasswordBytes, not equal to it. A password's byte
	// length is not recoverable from its argon2id hash, so it cannot be
	// proven against the live database that no account predating
	// MaxPasswordBytes holds a longer secret. Four times the current write
	// policy is far above anything a password manager emits and still bounds
	// the hash input to a few kilobytes. See issue #340.
	MaxVerifyPasswordBytes = 4 * MaxPasswordBytes
)

// Sentinel errors returned by validateEmail / validatePassword. Callers
// surface err.Error() directly to the client, so the strings are written as
// user-facing messages.
var (
	errEmailRequired = errors.New("Email is required.")
	errEmailTooLong  = fmt.Errorf("Email address must be at most %d characters.", MaxEmailBytes)
	errEmailInvalid  = errors.New("Please enter a valid email address.")

	errPasswordRequired   = errors.New("Password is required.")
	errPasswordTooShort   = fmt.Errorf("Password must be at least %d characters.", MinPasswordRunes)
	errPasswordTooLong    = fmt.Errorf("Password must be at most %d bytes.", MaxPasswordBytes)
	errPasswordWhitespace = errors.New("Password cannot consist only of whitespace.")
)

// validateEmail normalizes and validates a user-supplied email address,
// returning the canonical form to store (trimmed and lowercased).
//
// It is the single gate in front of every write that creates or changes a
// user's email: credential registration, OIDC auto-provisioning, and the
// email-change request. A validator that guards only one of those is not a
// validator — registering with a good address and then changing it would
// bypass the check entirely.
//
// It deliberately does NOT gate reads or logins. Accounts created before this
// existed may hold addresses that fail here; they must keep being able to log
// in, reset their password, and be looked up by email.
//
// Rules, and why:
//
//   - Trim + lowercase first, so "  A@B.com " and "a@b.com" are the same
//     account (users.email is UNIQUE and compared with =, not case-insensitively).
//   - Reject anything longer than MaxEmailBytes (RFC 5321).
//   - Reject any control character or interior whitespace. mail.ParseAddress
//     already rejects "a@b.com\nBcc: x@y.com", but SMTP header injection is
//     exactly the class of bug that must not depend on a stdlib implementation
//     detail, so it is checked explicitly.
//   - Parse with net/mail, matching validEmail in admin_settings.go.
//   - Require a *bare* address: no display name and byte-identical to the
//     input. mail.ParseAddress happily accepts "Foo <a@b.com>" (display-name
//     form) and `"a b"@c.com` (quoted local part, which it un-quotes to
//     "a b@c.com" — a stored address containing a space). Neither is a bare
//     mailbox, both would let two rows denote the same mailbox while passing
//     the UNIQUE constraint, and both are what an injection attempt looks
//     like. Rejected.
//
// Deliberately accepted: a dotless domain such as "a@b". It is RFC-valid and
// deliverable on the intranet/self-hosted deployments this app supports, and
// validEmail accepts it too.
func validateEmail(raw string) (string, error) {
	email := canonicalizeEmail(raw)
	if email == "" {
		return "", errEmailRequired
	}
	if len(email) > MaxEmailBytes {
		return "", errEmailTooLong
	}
	// After trimming, any remaining space/control byte is interior — a CR/LF
	// header-injection attempt, a NUL, or a malformed address.
	if strings.ContainsFunc(email, func(r rune) bool {
		return r == utf8.RuneError || r < 0x20 || r == 0x7f || unicode.IsSpace(r)
	}) {
		return "", errEmailInvalid
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", errEmailInvalid
	}
	if addr.Name != "" || addr.Address != email {
		return "", errEmailInvalid
	}
	return email, nil
}

// canonicalizeEmail is the normalization half of validateEmail — trim and
// lowercase — with none of the validation. It exists so that a READ path can
// bring a stored address into the canonical form before comparing it against
// one that came out of validateEmail, without also rejecting values that
// predate the validator.
//
// Splitting it out (rather than open-coding ToLower/TrimSpace at each
// comparison) is what keeps the two halves from drifting: validateEmail's
// return value is by construction canonicalizeEmail's output, so
// `canonicalizeEmail(stored) == validated` is exactly the right comparison.
//
// Never use it on a write. Anything that stores an address must call
// validateEmail, which is the only function that can reject one.
func canonicalizeEmail(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// validatePassword enforces the password policy on every write that sets a
// password: registration, password reset, and the change-password setting.
//
// Like validateEmail it gates writes only. Login must keep accepting whatever
// an existing account was created with, so verifyPassword never calls this.
//
// The whitespace-only rejection is a rejection, not a trim: trimming would
// silently change the secret the user typed.
func validatePassword(password string) error {
	if password == "" {
		return errPasswordRequired
	}
	// Cheapest check first: bail on an oversized body before touching it.
	if len(password) > MaxPasswordBytes {
		return errPasswordTooLong
	}
	if strings.TrimSpace(password) == "" {
		return errPasswordWhitespace
	}
	if utf8.RuneCountInString(password) < MinPasswordRunes {
		return errPasswordTooShort
	}
	return nil
}

// passwordExceedsVerifyCap reports whether a client-supplied password is too
// long to be handed to a password hash function on a *verification* path.
//
// It is deliberately not validatePassword: this is a cost bound, not the
// password policy. A grandfathered 9-character password must still log in;
// a 5 MB one must not be hashed. Callers treat a true result exactly like a
// wrong password — same response, same duration — so this must never grow
// into a second policy check whose outcome depends on anything but length.
func passwordExceedsVerifyCap(password string) bool {
	return len(password) > MaxVerifyPasswordBytes
}

// truncateUTF8 caps s at maxBytes bytes without splitting a multi-byte UTF-8
// rune. Byte-index slicing (s[:n]) can cut an emoji or other multi-byte rune
// in half, producing invalid UTF-8 that Postgres rejects with
// "invalid byte sequence for encoding UTF8" (error 22021). If the cap lands
// mid-rune, the cut point walks back to the previous rune boundary, so the
// result is always valid UTF-8 and a prefix of s.
func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// isValidDate reports whether s is a real calendar date in strict
// YYYY-MM-DD form within a sane year range. Unlike dateRe (a shape-only
// regex), the time.Parse round-trip rejects impossible dates such as
// 2026-02-31, which Postgres would reject with a query error (a 500 for the
// caller). The Format round-trip additionally rejects non-padded forms like
// 2026-7-3 that time.Parse tolerates.
func isValidDate(s string) bool {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return false
	}
	if t.Format("2006-01-02") != s {
		return false
	}
	y := t.Year()
	return y >= minDateYear && y <= maxDateYear
}

// entryCaloriesInRange reports whether amount satisfies the calorie_entries
// amount CHECK constraint (-MaxEntryCalories..MaxEntryCalories). Used to
// validate auto-computed calories, which can reach 16983 (999g protein +
// 999g carbs + 999g fat) — far beyond what the column accepts.
func entryCaloriesInRange(amount int) bool {
	return amount >= -MaxEntryCalories && amount <= MaxEntryCalories
}

// multiplyMacro multiplies an optional macro gram value by qty. ok is false
// when the result would violate the macro column CHECK constraint
// (0..MaxEntryMacro); a nil input passes through unchanged.
func multiplyMacro(v *int, qty int) (*int, bool) {
	if v == nil {
		return nil, true
	}
	m := *v * qty
	if m < 0 || m > MaxEntryMacro {
		return nil, false
	}
	return &m, true
}
