package service

import (
	"strings"
	"testing"
)

func TestGenerateCaptcha(t *testing.T) {
	c := GenerateCaptcha()
	if c.Text == "" {
		t.Error("captcha text is empty")
	}
	if len(c.Text) != 5 {
		t.Errorf("captcha text length = %d, want 5", len(c.Text))
	}
	if !strings.Contains(c.Data, "<svg") {
		t.Error("captcha data doesn't contain <svg")
	}
}

func TestVerifyCaptcha(t *testing.T) {
	tests := []struct {
		session, user string
		want          bool
	}{
		{"AbCdE", "AbCdE", true},
		{"AbCdE", "abcde", true},
		{"abcde", "ABCDE", true},
		{"abc", "  abc  ", true},
		{"  abc  ", "abc", true},
		{"abc", "xyz", false},
		{"", "abc", false},
		{"abc", "", false},
	}
	for _, tt := range tests {
		got := VerifyCaptcha(tt.session, tt.user)
		if got != tt.want {
			t.Errorf("VerifyCaptcha(%q, %q) = %v, want %v", tt.session, tt.user, got, tt.want)
		}
	}
}
