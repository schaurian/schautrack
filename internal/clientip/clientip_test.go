package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReq(remoteAddr, xff, xri string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = remoteAddr
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	if xri != "" {
		r.Header.Set("X-Real-Ip", xri)
	}
	return r
}

func TestFromRequest_TrustProxy(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		want       string
	}{
		{"remote addr only", "192.168.1.1:1234", "", "", "192.168.1.1"},
		{"xff single", "127.0.0.1:1234", "10.0.0.1", "", "10.0.0.1"},
		// Rightmost entry wins: it is appended by the trusted proxy and is the
		// only value the client cannot forge.
		{"xff multiple takes rightmost", "127.0.0.1:1234", "10.0.0.1, 10.0.0.2", "", "10.0.0.2"},
		{"xff three hops takes rightmost", "127.0.0.1:1234", "1.1.1.1, 2.2.2.2, 3.3.3.3", "", "3.3.3.3"},
		{"xff preferred over xri", "127.0.0.1:1234", "10.0.0.1", "10.0.0.5", "10.0.0.1"},
		{"xri used when no xff", "127.0.0.1:1234", "", "10.0.0.5", "10.0.0.5"},
		// Spoofing: an attacker prepends garbage; the proxy still appends the
		// real client, which is the rightmost valid IP.
		{"spoofed leftmost ignored", "127.0.0.1:1234", "6.6.6.6, 203.0.113.9", "", "203.0.113.9"},
		{"invalid rightmost skipped", "127.0.0.1:1234", "203.0.113.9, garbage", "", "203.0.113.9"},
		{"all-invalid xff falls back to xri", "127.0.0.1:1234", "junk, nope", "10.0.0.5", "10.0.0.5"},
		{"all-invalid xff and no xri falls back to remote", "192.168.1.9:1234", "junk", "", "192.168.1.9"},
		{"invalid xri ignored, falls back to remote", "192.168.1.9:1234", "", "not-an-ip", "192.168.1.9"},
		{"ipv6 remote addr", "[2001:db8::1]:1234", "", "", "2001:db8::1"},
		{"whitespace trimmed", "127.0.0.1:1234", "  10.0.0.1 ,  10.0.0.2  ", "", "10.0.0.2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromRequest(newReq(tt.remoteAddr, tt.xff, tt.xri), true)
			if got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFromRequest_SpoofingSameBucket is the core security property: whatever an
// attacker puts in the client-controlled (leftmost) XFF positions, the derived
// IP is stable, so they cannot rotate it to get a fresh rate-limit bucket.
func TestFromRequest_SpoofingSameBucket(t *testing.T) {
	a := FromRequest(newReq("127.0.0.1:1234", "1.2.3.4, 203.0.113.9", ""), true)
	b := FromRequest(newReq("127.0.0.1:1234", "9.9.9.9, 203.0.113.9", ""), true)
	c := FromRequest(newReq("127.0.0.1:1234", "203.0.113.9", ""), true)
	if a != b || b != c {
		t.Errorf("spoofed leftmost changed the key: %q, %q, %q (want all equal)", a, b, c)
	}
}

func TestFromRequest_NoTrustProxy(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		want       string
	}{
		{"ignores xff", "192.168.1.1:1234", "10.0.0.1", "", "192.168.1.1"},
		{"ignores xri", "192.168.1.1:1234", "", "10.0.0.5", "192.168.1.1"},
		{"ignores both", "192.168.1.1:1234", "10.0.0.1, 10.0.0.2", "10.0.0.5", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromRequest(newReq(tt.remoteAddr, tt.xff, tt.xri), false)
			if got != tt.want {
				t.Errorf("FromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}
