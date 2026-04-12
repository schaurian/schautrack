package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

type rateLimitEntry struct {
	count    int
	windowStart time.Time
}

type RateLimiter struct {
	mu         sync.Mutex
	entries    map[string]*rateLimitEntry
	max        int
	window     time.Duration
	maxEntries int
	trustProxy bool
}

const defaultMaxEntries = 10000

func NewRateLimiter(max int, window time.Duration, trustProxy bool) *RateLimiter {
	rl := &RateLimiter{
		entries:    make(map[string]*rateLimitEntry),
		max:        max,
		window:     window,
		maxEntries: defaultMaxEntries,
		trustProxy: trustProxy,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r, rl.trustProxy)

		rl.mu.Lock()
		entry, ok := rl.entries[ip]
		now := time.Now()

		if !ok || now.Sub(entry.windowStart) > rl.window {
			// Cap the number of tracked IPs to prevent unbounded memory growth
			// (e.g. behind a CDN or with spoofed X-Forwarded-For headers).
			if !ok && len(rl.entries) >= rl.maxEntries {
				rl.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]any{
					"error": "Too many attempts. Please try again later.",
				})
				return
			}
			rl.entries[ip] = &rateLimitEntry{count: 1, windowStart: now}
			rl.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		entry.count++
		if entry.count > rl.max {
			rl.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]any{
				"error": "Too many attempts. Please try again later.",
			})
			return
		}
		rl.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, entry := range rl.entries {
			if now.Sub(entry.windowStart) > rl.window {
				delete(rl.entries, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// clientIP extracts the client IP from the request. When trustProxy is true,
// it reads X-Forwarded-For and X-Real-Ip headers set by a reverse proxy or
// Kubernetes ingress. When false, it uses RemoteAddr directly to prevent
// clients from spoofing their IP.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			for i := 0; i < len(xff); i++ {
				if xff[i] == ',' {
					return xff[:i]
				}
			}
			return xff
		}
		if xri := r.Header.Get("X-Real-Ip"); xri != "" {
			return xri
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}
