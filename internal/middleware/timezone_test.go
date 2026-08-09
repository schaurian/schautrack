package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

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

func TestRememberClientTimezoneSetsSecureCookieForSecureRequests(t *testing.T) {
	cases := []struct {
		name       string
		forwarded  string
		tls        bool
		wantSecure bool
	}{
		{"plain HTTP", "", false, false},
		{"TLS", "", true, true},
		{"TLS at proxy", "https", false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("X-Timezone", "Europe/Berlin")
			req.Header.Set("X-Forwarded-Proto", tc.forwarded)
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			rec := httptest.NewRecorder()

			RememberClientTimezone(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

			cookies := rec.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatalf("cookie count = %d, want 1", len(cookies))
			}
			if got := cookies[0].Secure; got != tc.wantSecure {
				t.Errorf("Secure = %t, want %t", got, tc.wantSecure)
			}
		})
	}
}
