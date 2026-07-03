// Package clientip derives the originating client IP from an HTTP request.
//
// It is shared by the rate limiter (internal/middleware) and the audit logger
// (internal/service) so both agree on the same value and cannot drift. It lives
// in its own leaf package to avoid a service ↔ middleware import cycle.
package clientip

import (
	"net"
	"net/http"
	"strings"
)

// FromRequest returns the client IP for rate limiting and audit logging.
//
// When trustProxy is true (the default for k8s/Docker deployments sitting
// behind a trusted reverse proxy or ingress) it derives the IP from proxy
// headers. It deliberately uses the RIGHTMOST entry of X-Forwarded-For — the
// address appended by the closest trusted proxy — because every entry to its
// left is client-supplied and trivially forgeable. Trusting the leftmost value
// (the previous behaviour) let an attacker rotate X-Forwarded-For on each
// request to land in a fresh rate-limit bucket, defeating the brute-force gate
// on login, 2FA and password reset.
//
// When trustProxy is false, proxy headers are ignored entirely and RemoteAddr
// is used, so a directly-exposed instance cannot be spoofed.
func FromRequest(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if ip := rightmostForwarded(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
		if xri := strings.TrimSpace(r.Header.Get("X-Real-Ip")); xri != "" && net.ParseIP(xri) != nil {
			return xri
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

// rightmostForwarded returns the last syntactically-valid IP in a
// comma-separated X-Forwarded-For header, or "" if there is none. Scanning
// right-to-left yields the entry appended by the nearest trusted proxy; a
// downstream client can only prepend values, never append past the proxy.
func rightmostForwarded(xff string) string {
	if xff == "" {
		return ""
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}
