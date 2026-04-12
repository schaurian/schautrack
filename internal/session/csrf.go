package session

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// GenerateCsrfToken creates or returns the CSRF token stored in the session.
func GenerateCsrfToken(sess *Session) string {
	if token := sess.GetString("csrfToken"); token != "" {
		return token
	}
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)
	sess.Set("csrfToken", token)
	return token
}

// ValidateCsrfToken checks the X-CSRF-Token header against the session value.
func ValidateCsrfToken(r *http.Request, sess *Session) bool {
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		// Fallback: check body _csrf field (for multipart forms)
		// We don't parse body here; handlers that need this can pass it
		return false
	}
	sessToken := sess.GetString("csrfToken")
	if sessToken == "" || len(token) != len(sessToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(sessToken)) == 1
}

// CsrfProtection is middleware that validates CSRF on state-changing requests.
func CsrfProtection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		sess := GetSession(r)
		if sess == nil || !ValidateCsrfToken(r, sess) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{
				"error": "Invalid CSRF token",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}
