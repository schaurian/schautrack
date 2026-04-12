package middleware

import "net/http"

// MaxBodySize limits the size of incoming request bodies.
// This is a defense-in-depth measure; individual handlers may enforce
// tighter limits via ReadJSON or io.LimitReader.
func MaxBodySize(bytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, bytes)
			next.ServeHTTP(w, r)
		})
	}
}
