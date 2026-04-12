package middleware

import (
	"net/http"
	"time"
)

// RememberClientTimezone stores the client's timezone from the X-Timezone header
// into a cookie for future reference.
func RememberClientTimezone(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tz := r.Header.Get("X-Timezone")
		if tz != "" {
			// Validate it's a real timezone
			if _, err := time.LoadLocation(tz); err == nil {
				http.SetCookie(w, &http.Cookie{
					Name:     "timezone",
					Value:    tz,
					Path:     "/",
					MaxAge:   365 * 24 * 60 * 60,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
				})
			}
		}
		next.ServeHTTP(w, r)
	})
}

// GetClientTimezone returns the timezone from the X-Timezone header or cookie.
func GetClientTimezone(r *http.Request) string {
	if tz := r.Header.Get("X-Timezone"); tz != "" {
		return tz
	}
	if c, err := r.Cookie("timezone"); err == nil {
		return c.Value
	}
	return ""
}
