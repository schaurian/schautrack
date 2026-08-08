package middleware

import "testing"

func TestNormalizeTimezone(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"UTC", "UTC"},
		{"Europe/Berlin", "Europe/Berlin"},
		{"Europe%2FBerlin", "Europe/Berlin"}, // legacy URL-encoded cookies
		{"America%2FArgentina%2FBuenos_Aires", "America/Argentina/Buenos_Aires"},
		{"Not/A/Zone", ""},
		{"Europe%ZZBerlin", ""}, // invalid percent-encoding falls through to LoadLocation, which fails
	}
	for _, c := range cases {
		got := normalizeTimezone(c.in)
		if got != c.want {
			t.Errorf("normalizeTimezone(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
