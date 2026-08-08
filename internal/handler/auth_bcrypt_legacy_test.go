package handler

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Legacy bcrypt hashes are still accepted by verifyPassword and were covered by
// nothing (#371): a grep for `$2[aby]$` across internal/ found no test at all.
//
// That branch is load-bearing in two directions. Accounts created before the
// argon2id switch still authenticate through it, and the E2E suite seeds users
// by writing bcrypt hashes directly — since #323 those come from bcryptjs, so
// "does the app accept what bcryptjs produces?" had no answer in Go.
//
// Costs are deliberately kept at bcrypt.MinCost: these assert routing and
// acceptance, not work factor, and a default-cost hash per case would make the
// package noticeably slower for nothing.

func bcryptHashAtCost(t *testing.T, password string, cost int) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		t.Fatalf("generating a bcrypt hash: %v", err)
	}
	return string(h)
}

func TestVerifyPasswordAcceptsLegacyBcrypt(t *testing.T) {
	const password = "correct horse battery staple"
	hash := bcryptHashAtCost(t, password, bcrypt.MinCost)

	if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
		t.Fatalf("hash %.4q has neither prefix verifyPassword routes on", hash)
	}

	ok, err := verifyPassword(hash, password)
	if err != nil {
		t.Fatalf("verifyPassword returned an error: %v", err)
	}
	if !ok {
		t.Error("a correct password did not verify against its bcrypt hash")
	}

	if ok, _ := verifyPassword(hash, password+"x"); ok {
		t.Error("a wrong password verified against a bcrypt hash")
	}
}

// TestVerifyPasswordAcceptsBcryptjsHashes uses hashes produced by the bcryptjs
// the E2E seeds now use (#323), pasted as literals so this does not depend on
// Node being installed. bcryptjs emits $2b$, which golang.org/x/crypto/bcrypt
// accepts; if that ever stopped being true the suite would fail at "Setup
// failed" with no explanation, long before any spec ran.
func TestVerifyPasswordAcceptsBcryptjsHashes(t *testing.T) {
	// Generated with the repo's own bcryptjs and verified by it before being
	// pasted here:
	//
	//	node -e 'const b=require("bcryptjs");const h=b.hashSync("test1234test",10);
	//	         console.log(h, b.compareSync("test1234test", h))'
	//
	// "test1234test" is the password e2e/setup-test-user.ts seeds, so this is
	// the exact byte sequence the suite writes into users.password_hash.
	cases := []struct{ password, hash string }{
		{"test1234test", "$2b$10$.UMNLvyRn.SDYPy2FnxITundj6wLEYzWsigw7mx/Jfa/9zcFXbFU6"},
		{"link-test-pw", "$2b$10$K4V09fZ3YXfQC1OMLwmApOWRD2RiW0zTg/pfZl3538q9kU/mCCH3a"},
	}
	for _, c := range cases {
		ok, err := verifyPassword(c.hash, c.password)
		if err != nil {
			t.Fatalf("verifyPassword(%.7q…): %v", c.hash, err)
		}
		if !ok {
			t.Errorf("a bcryptjs $2b$ hash was rejected — the E2E seeds would fail before any spec ran")
		}
	}
}

// TestVerifyPasswordRoutesOnThePrefix pins the branch itself: an argon2id hash
// must not be handed to bcrypt and vice versa. The two formats are
// distinguishable only by prefix, and getting the routing wrong fails closed
// (every login rejected) rather than open — but silently, and for everyone.
func TestVerifyPasswordRoutesOnThePrefix(t *testing.T) {
	const password = "another password entirely"

	argonHash, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !strings.HasPrefix(argonHash, "$argon2id$") {
		t.Fatalf("hashPassword produced %.10q, want an $argon2id$ hash", argonHash)
	}
	if ok, err := verifyPassword(argonHash, password); err != nil || !ok {
		t.Errorf("argon2id hash did not verify (ok=%v, err=%v)", ok, err)
	}

	// A bcrypt hash must not verify a password it does not match, even though
	// both formats start with "$".
	bcryptHash := bcryptHashAtCost(t, password, bcrypt.MinCost)
	if ok, _ := verifyPassword(bcryptHash, "wrong"); ok {
		t.Error("bcrypt branch accepted a wrong password")
	}

	// An unrecognised format falls through to the argon2id comparison, which
	// errors rather than accepting. Asserting it never returns true is the
	// property that matters.
	if ok, _ := verifyPassword("$2y$10$notarealhashvalue", password); ok {
		t.Error("an unsupported hash format verified")
	}
}
