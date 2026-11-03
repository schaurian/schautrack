package middleware

import "net/http"

// SecurityHeaders sets security-related HTTP headers (CSP, HSTS, etc.).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"font-src 'self'; "+
				"img-src 'self' data: blob:; "+
				"script-src 'self'; "+
				// Neither of these falls back to default-src. frame-ancestors is
				// the CSP form of X-Frame-Options (kept for old browsers);
				// base-uri stops an injected <base> from re-pointing every
				// relative script URL. object-src is explicit rather than
				// inherited so a widened default-src cannot let plugins in.
				"frame-ancestors 'self'; "+
				"base-uri 'self'; "+
				"object-src 'none'")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Origin-Agent-Cluster", "?1")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=15552000; includeSubDomains")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-DNS-Prefetch-Control", "off")
		w.Header().Set("X-Download-Options", "noopen")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		w.Header().Set("X-XSS-Protection", "0")
		next.ServeHTTP(w, r)
	})
}
