package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"
)

// Recovery catches panics and returns a 500 JSON response.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic: %v\n%s", rec, debug.Stack())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]any{
					"ok":    false,
					"error": "Internal server error",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}
