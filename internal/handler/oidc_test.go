package handler

import "testing"

func TestSafeNextPath(t *testing.T) {
	const fb = "/settings"
	tests := []struct {
		name string
		next string
		want string
	}{
		{"empty falls back", "", fb},
		{"simple path", "/dashboard", "/dashboard"},
		{"nested path", "/settings/security", "/settings/security"},
		{"path with query kept", "/foods?tab=recent", "/foods?tab=recent"},
		{"root path", "/", "/"},

		// Open-redirect vectors that must all fall back.
		{"protocol relative", "//evil.com", fb},
		{"backslash obfuscation", "/\\evil.com", fb},
		{"backslash double", "/\\/evil.com", fb},
		{"absolute http url", "http://evil.com", fb},
		{"absolute https url", "https://evil.com/path", fb},
		{"scheme relative with backslashes", "\\\\evil.com", fb},
		{"javascript scheme", "javascript:alert(1)", fb},
		{"no leading slash", "evil.com", fb},
		{"leading space then slash", " /dashboard", fb},
		{"embedded newline", "/foo\nbar", fb},
		{"embedded CR", "/foo\rbar", fb},
		{"null byte", "/foo\x00bar", fb},
		{"tab char", "/foo\tbar", fb},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeNextPath(tt.next, fb); got != tt.want {
				t.Errorf("safeNextPath(%q) = %q, want %q", tt.next, got, tt.want)
			}
		})
	}
}
