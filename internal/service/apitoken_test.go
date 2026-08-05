package service

import (
	"encoding/base64"
	"strings"
	"testing"
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
