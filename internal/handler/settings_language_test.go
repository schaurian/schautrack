package handler

import "testing"

func TestNormalizeLanguage(t *testing.T) {
	cases := map[string]string{
		"de":    "de",
		"EN":    "en",
		" fr ":  "fr",
		"":      "",   // Automatic
		"xx":    "",   // unsupported -> Automatic
		"de-DE": "de", // region stripped
		"pt_BR": "pt", // underscore region stripped
	}
	for in, want := range cases {
		if got := normalizeLanguage(in); got != want {
			t.Errorf("normalizeLanguage(%q) = %q, want %q", in, got, want)
		}
	}
}
