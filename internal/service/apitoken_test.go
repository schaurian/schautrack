package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"schautrack/internal/database"
	"schautrack/internal/model"
)

func TestGenerateAPITokenShape(t *testing.T) {
	raw, digest, prefix, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}

	if !strings.HasPrefix(raw, TokenPrefix) {
		t.Errorf("raw = %q, want the %q prefix so secret scanners can spot it", raw, TokenPrefix)
	}
	if !strings.HasPrefix(prefix, TokenPrefix) || len(prefix) != len(TokenPrefix)+prefixDisplayLen {
		t.Errorf("prefix = %q, want %q + %d chars", prefix, TokenPrefix, prefixDisplayLen)
	}
	if !strings.HasPrefix(raw, prefix) {
		t.Errorf("prefix %q is not a prefix of raw %q", prefix, raw)
	}
	if len(digest) != 32 {
		t.Errorf("digest length = %d, want 32 (SHA-256)", len(digest))
	}

	// The secret must decode to the full entropy we claim to generate.
	secret := strings.TrimPrefix(raw, TokenPrefix)
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		t.Fatalf("secret is not base64url: %v", err)
	}
	if len(decoded) != tokenEntropyBytes {
		t.Errorf("entropy = %d bytes, want %d", len(decoded), tokenEntropyBytes)
	}
}

func TestGenerateAPITokenIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 500 {
		raw, _, _, err := GenerateAPIToken()
		if err != nil {
			t.Fatalf("GenerateAPIToken: %v", err)
		}
		if seen[raw] {
			t.Fatal("GenerateAPIToken produced a duplicate — the RNG is not doing its job")
		}
		seen[raw] = true
	}
}

func TestHashAPITokenMatchesGeneration(t *testing.T) {
	raw, digest, _, err := GenerateAPIToken()
	if err != nil {
		t.Fatalf("GenerateAPIToken: %v", err)
	}
	again := HashAPIToken(raw)
	if string(again) != string(digest) {
		t.Error("HashAPIToken(raw) does not match the digest returned at generation")
	}
	if string(HashAPIToken(raw+"x")) == string(digest) {
		t.Error("a modified token hashed to the same digest")
	}
}

func TestParseBearer(t *testing.T) {
	tests := []struct {
		name, header, want string
	}{
		{"standard", "Bearer stk_abc", "stk_abc"},
		{"lowercase scheme", "bearer stk_abc", "stk_abc"},
		{"mixed case scheme", "BeArEr stk_abc", "stk_abc"},
		{"extra whitespace", "Bearer    stk_abc  ", "stk_abc"},
		{"empty header", "", ""},
		{"no scheme", "stk_abc", ""},
		{"basic auth is not a bearer token", "Basic dXNlcjpwYXNz", ""},
		{"scheme only", "Bearer ", ""},
		{"prefix of scheme", "Bear stk_abc", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseBearer(tt.header); got != tt.want {
				t.Errorf("ParseBearer(%q) = %q, want %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestLooksLikeAPIToken(t *testing.T) {
	raw, _, _, _ := GenerateAPIToken()
	tests := []struct {
		in   string
		want bool
	}{
		{raw, true},
		{"", false},
		{"stk_", false},
		{"stk_short", false},
		{"ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"Bearer " + raw, false},
	}
	for _, tt := range tests {
		if got := LooksLikeAPIToken(tt.in); got != tt.want {
			t.Errorf("LooksLikeAPIToken(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestValidateScopes(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    []string
		wantErr bool
	}{
		{"single", []string{"entries:read"}, []string{"entries:read"}, false},
		{"sorted canonically", []string{"weight:read", "entries:read"}, []string{"entries:read", "weight:read"}, false},
		{"deduplicated", []string{"entries:read", "entries:read"}, []string{"entries:read"}, false},
		{"trimmed and lowercased", []string{"  ENTRIES:READ  "}, []string{"entries:read"}, false},
		{"blank entries ignored", []string{"entries:read", "", "  "}, []string{"entries:read"}, false},
		{"unknown scope rejected", []string{"entries:read", "entries:destroy"}, nil, true},
		{"empty rejected", nil, nil, true},
		{"only blanks rejected", []string{"", " "}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateScopes(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateScopes(%v) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("ValidateScopes(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateScopesAcceptsEveryDocumentedScope(t *testing.T) {
	got, err := ValidateScopes(AllScopes())
	if err != nil {
		t.Fatalf("AllScopes() is not accepted by ValidateScopes: %v", err)
	}
	if len(got) != len(AllScopes()) {
		t.Errorf("got %d scopes, want %d — AllScopes has duplicates", len(got), len(AllScopes()))
	}
}

func TestScopeSatisfies(t *testing.T) {
	tests := []struct {
		name     string
		granted  []string
		required string
		want     bool
	}{
		{"exact match", []string{"entries:read"}, "entries:read", true},
		{"write implies read", []string{"entries:write"}, "entries:read", true},
		{"read does NOT imply write", []string{"entries:read"}, "entries:write", false},
		{"unrelated resource", []string{"weight:write"}, "entries:read", false},
		{"one of several", []string{"weight:read", "entries:write"}, "entries:write", true},
		{"empty grants nothing", nil, "entries:read", false},
		{"plan:read has no write to imply it", []string{"plan:read"}, "plan:read", true},
		{"write of another resource does not imply this read", []string{"foods:write"}, "notes:read", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ScopeSatisfies(tt.granted, tt.required); got != tt.want {
				t.Errorf("ScopeSatisfies(%v, %q) = %v, want %v", tt.granted, tt.required, got, tt.want)
			}
		})
	}
}

// activeInList counts the tokens a caller reading ListAPITokens would consider
// live — the same subset the token UI renders as usable. It exists so the test
// below can compare the list's answer against the cap's answer.
func activeInList(tokens []model.APIToken, now time.Time) int {
	n := 0
	for _, t := range tokens {
		if t.Active(now) {
			n++
		}
	}
	return n
}

// TestListAndCapAgreeOnWhatCountsAgainstTheLimit is the regression test for
// issue #299: ListAPITokens kept expired tokens while the mint cap ignored
// them, and the UI — which gates its "New token" button on the list — locked
// users out of tokens the server would have granted.
//
// The two must stay reconcilable: whatever ListAPITokens returns, the number of
// entries satisfying model.APIToken.Active has to equal CountActiveAPITokens,
// which is the number CreateAPIToken enforces against. This test drives a user
// through the states where they diverged.
//
// Skipped unless TEST_DATABASE_URL is set, so it does not gate CI (which has no
// database). Run locally with, e.g.:
//
//	TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./internal/service/ -run TestListAndCapAgreeOnWhatCountsAgainstTheLimit -v
func TestListAndCapAgreeOnWhatCountsAgainstTheLimit(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer pool.Close()

	if err := database.InitSchemaWithRetry(ctx, pool, 3); err != nil {
		t.Fatalf("schema init failed: %v", err)
	}

	email := fmt.Sprintf("apitoken-limit-test-%d@example.com", time.Now().UnixNano())
	var userID int
	if err := pool.QueryRow(ctx,
		"INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id", email,
	).Scan(&userID); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	defer pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", userID)

	// assertAgreement is the invariant, checked after every state change: the
	// list and the cap must describe the same set of live tokens.
	assertAgreement := func(t *testing.T, wantListed, wantActive int) {
		t.Helper()
		tokens, err := ListAPITokens(ctx, pool, userID)
		if err != nil {
			t.Fatalf("ListAPITokens failed: %v", err)
		}
		if len(tokens) != wantListed {
			t.Errorf("ListAPITokens returned %d tokens, want %d", len(tokens), wantListed)
		}
		counted, err := CountActiveAPITokens(ctx, pool, userID)
		if err != nil {
			t.Fatalf("CountActiveAPITokens failed: %v", err)
		}
		if listActive := activeInList(tokens, time.Now()); listActive != counted {
			t.Errorf("the list says %d active tokens, the cap counts %d — they must agree",
				listActive, counted)
		}
		if counted != wantActive {
			t.Errorf("CountActiveAPITokens = %d, want %d", counted, wantActive)
		}
	}

	mint := func(t *testing.T, name string) *model.APIToken {
		t.Helper()
		expiry := time.Now().Add(24 * time.Hour)
		tok, raw, err := CreateAPIToken(ctx, pool, userID, name, []string{ScopeEntriesRead}, &expiry)
		if err != nil {
			t.Fatalf("CreateAPIToken(%q) failed: %v", name, err)
		}
		if !strings.HasPrefix(raw, TokenPrefix) {
			t.Fatalf("CreateAPIToken(%q) returned a malformed secret", name)
		}
		return tok
	}

	// Fill the account to exactly the cap.
	for i := range MaxTokensPerUser {
		mint(t, fmt.Sprintf("token-%02d", i))
	}
	assertAgreement(t, MaxTokensPerUser, MaxTokensPerUser)

	// At the cap, minting must be refused — this is the state the UI's "at the
	// limit" message is supposed to describe.
	expiry := time.Now().Add(24 * time.Hour)
	if _, _, err := CreateAPIToken(ctx, pool, userID, "one too many",
		[]string{ScopeEntriesRead}, &expiry); !errors.Is(err, ErrTokenLimit) {
		t.Fatalf("CreateAPIToken at the cap returned %v, want ErrTokenLimit", err)
	}

	// Now let 8 of them lapse. The list must still show all 20 (the user has to
	// be able to see and clear the dead ones) while only 12 count.
	const expiredCount = 8
	if _, err := pool.Exec(ctx, `
		UPDATE api_tokens SET expires_at = NOW() - INTERVAL '1 day'
		WHERE id IN (SELECT id FROM api_tokens WHERE user_id = $1 ORDER BY id LIMIT $2)`,
		userID, expiredCount); err != nil {
		t.Fatalf("failed to expire tokens: %v", err)
	}
	assertAgreement(t, MaxTokensPerUser, MaxTokensPerUser-expiredCount)

	// The payoff: with expired tokens on the account the server grants another
	// one. Before the fix the UI refused to even render the button here.
	fresh := mint(t, "after the lapse")
	assertAgreement(t, MaxTokensPerUser+1, MaxTokensPerUser-expiredCount+1)

	// Revocation removes a token from the list and the count together — the
	// one case where the two have always agreed, asserted so it stays that way.
	ok, err := RevokeAPIToken(ctx, pool, userID, fresh.ID)
	if err != nil || !ok {
		t.Fatalf("RevokeAPIToken(%d) = %v, %v; want true, nil", fresh.ID, ok, err)
	}
	assertAgreement(t, MaxTokensPerUser, MaxTokensPerUser-expiredCount)

	// An expired token can still be revoked, which is how a user clears the
	// dead weight the list now shows them.
	tokens, err := ListAPITokens(ctx, pool, userID)
	if err != nil {
		t.Fatalf("ListAPITokens failed: %v", err)
	}
	var expiredID int
	for _, tok := range tokens {
		if !tok.Active(time.Now()) {
			expiredID = tok.ID
			break
		}
	}
	if expiredID == 0 {
		t.Fatal("expected at least one expired token in the list")
	}
	if ok, err := RevokeAPIToken(ctx, pool, userID, expiredID); err != nil || !ok {
		t.Fatalf("RevokeAPIToken(expired %d) = %v, %v; want true, nil", expiredID, ok, err)
	}
	assertAgreement(t, MaxTokensPerUser-1, MaxTokensPerUser-expiredCount)
}

// TestEveryScopeHasADescription guards the token UI and the generated docs:
// both render from ScopeDescriptions, so a scope constant without an entry
// would be grantable but invisible.
func TestEveryScopeHasADescription(t *testing.T) {
	for _, d := range ScopeDescriptions {
		if strings.TrimSpace(d.Description) == "" {
			t.Errorf("scope %q has no description", d.Scope)
		}
		if !strings.Contains(d.Scope, ":") {
			t.Errorf("scope %q is not in resource:action form", d.Scope)
		}
	}
}
