package service

import (
	"strings"
	"testing"
)

// TestRenderEmailLocale_German verifies that a supported non-English locale
// renders a translated subject and includes the interpolated code in the
// text body.
func TestRenderEmailLocale_German(t *testing.T) {
	rendered, err := renderEmail("verification", "de", map[string]any{"Code": "123456"})
	if err != nil {
		t.Fatalf("renderEmail returned error: %v", err)
	}
	if rendered.Subject == "" {
		t.Error("Subject is empty, want a non-empty translated subject")
	}
	if !strings.Contains(rendered.Text, "123456") {
		t.Errorf("Text = %q, want it to contain the code %q", rendered.Text, "123456")
	}
}

// TestRenderEmailLocale_UnknownFallsBackToEnglish verifies that an
// unsupported/unknown locale silently falls back to "en" rather than
// erroring or rendering empty content.
func TestRenderEmailLocale_UnknownFallsBackToEnglish(t *testing.T) {
	unknown, err := renderEmail("verification", "xx", map[string]any{"Code": "123456"})
	if err != nil {
		t.Fatalf("renderEmail(\"xx\") returned error: %v", err)
	}
	english, err := renderEmail("verification", "en", map[string]any{"Code": "123456"})
	if err != nil {
		t.Fatalf("renderEmail(\"en\") returned error: %v", err)
	}
	if unknown.Subject != english.Subject {
		t.Errorf("unknown locale Subject = %q, want it to match English fallback %q", unknown.Subject, english.Subject)
	}
}
