package middleware

import (
	"net/http"
	"net/url"
	"time"
)

// normalizeTimezone decodes a possibly URL-encoded IANA zone and returns it
// only if it parses as a real location. Covers legacy cookies from the old
// Node.js backend that stored values like "Europe%2FBerlin" via Express's
// default cookie encoding.
func normalizeTimezone(raw string) string {
	if raw == "" {
		return ""
	}
	candidate := raw
	if decoded, err := url.QueryUnescape(raw); err == nil {
		candidate = decoded
	}
	if _, err := time.LoadLocation(candidate); err != nil {
		return ""
	}
	return candidate
}

// RememberClientTimezone stores the client's timezone from the X-Timezone header
// into a cookie for future reference.
func RememberClientTimezone(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tz := normalizeTimezone(r.Header.Get("X-Timezone")); tz != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     "timezone",
				Value:    tz,
				Path:     "/",
				MaxAge:   365 * 24 * 60 * 60,
				HttpOnly: true,
				Secure:   requestSecure(r),
				SameSite: http.SameSiteLaxMode,
			})
		}
		next.ServeHTTP(w, r)
	})
}

// requestSecure reports whether the request arrived over TLS, either directly
// or through a reverse proxy that terminated TLS.
func requestSecure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// GetClientTimezone returns the timezone from the X-Timezone header or cookie.
func GetClientTimezone(r *http.Request) string {
	if tz := normalizeTimezone(r.Header.Get("X-Timezone")); tz != "" {
		return tz
	}
	if c, err := r.Cookie("timezone"); err == nil {
		if tz := normalizeTimezone(c.Value); tz != "" {
			return tz
		}
	}
	return ""
}
