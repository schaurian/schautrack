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
	svgAnswer, altAnswer := splitCaptchaToken(c.Text)
	if len(svgAnswer) != 5 {
		t.Errorf("visual captcha answer length = %d, want 5", len(svgAnswer))
	}
	if altAnswer == "" {
		t.Error("non-visual challenge answer is empty")
	}
	if !strings.Contains(c.Data, "<svg") {
		t.Error("captcha data doesn't contain <svg")
	}
	if c.Question == "" {
		t.Error("non-visual captcha question is empty")
	}
	// Both the visual and the non-visual answer must verify against the secret.
	if !VerifyCaptcha(c.Text, svgAnswer) {
		t.Error("generated visual answer does not verify")
	}
	if !VerifyCaptcha(c.Text, altAnswer) {
		t.Error("generated non-visual answer does not verify")
	}
}

func TestVerifyCaptcha_AltChallenge(t *testing.T) {
	// Session secret bundling the visual answer "AbCdE" and the arithmetic
	// answer "7" ("What is four plus three?").
	const session = "AbCdE|7"
	tests := []struct {
		user string
		want bool
	}{
		{"AbCdE", true},   // visual answer, exact
		{"abcde", true},   // visual answer, case-insensitive
		{"7", true},       // non-visual answer as digits
		{"seven", true},   // non-visual answer spelled out
		{" SEVEN ", true}, // spelled, padded, case-insensitive
		{"8", false},      // wrong number
		{"eight", false},  // wrong spelled number
		{"", false},       // empty
	}
	for _, tt := range tests {
		if got := VerifyCaptcha(session, tt.user); got != tt.want {
			t.Errorf("VerifyCaptcha(%q, %q) = %v, want %v", session, tt.user, got, tt.want)
		}
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
