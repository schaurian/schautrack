package middleware

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"schautrack/internal/apierr"
	"schautrack/internal/clientip"
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

	// reject writes the 429. It is a field so the /api/v1 limiter can emit
	// problem+json while the legacy limiters keep their {"error": ...} shape —
	// every response from /api/v1 must be problem+json, including the ones
	// produced before any handler runs.
	//
	// Read through rejectFn, never directly: a zero-value RateLimiter (which
	// the tests build as a struct literal) leaves this nil.
	reject func(http.ResponseWriter, *http.Request)
}

// rejectFn returns the configured rejection writer, defaulting to the legacy
// JSON shape so a struct-literal RateLimiter still works.
func (rl *RateLimiter) rejectFn() func(http.ResponseWriter, *http.Request) {
	if rl.reject != nil {
		return rl.reject
	}
	return rejectJSON
}

const defaultMaxEntries = 10000

func NewRateLimiter(max int, window time.Duration, trustProxy bool) *RateLimiter {
	rl := &RateLimiter{
		entries:    make(map[string]*rateLimitEntry),
		max:        max,
		window:     window,
		maxEntries: defaultMaxEntries,
		trustProxy: trustProxy,
		reject:     rejectJSON,
	}
	go rl.cleanup()
	return rl
}

// NewProblemRateLimiter is NewRateLimiter with RFC 9457 rejections, for use on
// the public API surface.
func NewProblemRateLimiter(max int, window time.Duration, trustProxy bool) *RateLimiter {
	rl := NewRateLimiter(max, window, trustProxy)
	rl.reject = func(w http.ResponseWriter, r *http.Request) {
		apierr.Write(w, r, apierr.TooManyRequests(
			"You have made too many requests. Slow down and try again shortly."))
	}
	return rl
}

func rejectJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	json.NewEncoder(w).Encode(map[string]any{
		"error": "Too many attempts. Please try again later.",
	})
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
				rl.rejectFn()(w, r)
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
			rl.rejectFn()(w, r)
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

// clientIP extracts the client IP used as the rate-limit bucket key. It
// delegates to the shared clientip.FromRequest so the limiter and the audit
// logger derive the same, non-spoofable value from proxy headers.
func clientIP(r *http.Request, trustProxy bool) string {
	return clientip.FromRequest(r, trustProxy)
}
