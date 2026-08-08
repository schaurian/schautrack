package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"schautrack/internal/apierr"
	"schautrack/internal/clientip"
)

type rateLimitEntry struct {
	count       int
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
	//
	// retryAfter is how long until the caller's window resets, so the rejection
	// can say when to come back instead of leaving the client to guess.
	reject func(w http.ResponseWriter, r *http.Request, retryAfter time.Duration)

	// keyFn chooses the bucket. Nil means bucket by client IP.
	keyFn func(*http.Request) string
}

// bucketKey returns the rate-limit bucket for a request.
func (rl *RateLimiter) bucketKey(r *http.Request) string {
	if rl.keyFn != nil {
		return rl.keyFn(r)
	}
	return clientIP(r, rl.trustProxy)
}

// rejectFn returns the configured rejection writer, defaulting to the legacy
// JSON shape so a struct-literal RateLimiter still works.
func (rl *RateLimiter) rejectFn() func(http.ResponseWriter, *http.Request, time.Duration) {
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
	go rl.cleanup(context.Background())
	return rl
}

// NewProblemRateLimiter is NewRateLimiter with RFC 9457 rejections, for use on
// the public API surface.
func NewProblemRateLimiter(max int, window time.Duration, trustProxy bool) *RateLimiter {
	rl := NewRateLimiter(max, window, trustProxy)
	rl.reject = func(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
		setRetryAfter(w, retryAfter)
		apierr.Write(w, r, apierr.TooManyRequests(fmt.Sprintf(
			"You have made too many requests. Retry in %d seconds.", retryAfterSeconds(retryAfter))))
	}
	return rl
}

func rejectJSON(w http.ResponseWriter, _ *http.Request, retryAfter time.Duration) {
	setRetryAfter(w, retryAfter)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	json.NewEncoder(w).Encode(map[string]any{
		"error": "Too many attempts. Please try again later.",
	})
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := rl.bucketKey(r)

		rl.mu.Lock()
		entry, ok := rl.entries[ip]
		now := time.Now()

		if !ok || now.Sub(entry.windowStart) > rl.window {
			// Cap the number of tracked IPs to prevent unbounded memory growth
			// (e.g. behind a CDN or with spoofed X-Forwarded-For headers).
			if !ok && len(rl.entries) >= rl.maxEntries {
				rl.mu.Unlock()
				rl.rejectFn()(w, r, rl.window)
				return
			}
			rl.entries[ip] = &rateLimitEntry{count: 1, windowStart: now}
			rl.mu.Unlock()
			next.ServeHTTP(w, r)
			return
		}

		entry.count++
		if entry.count > rl.max {
			retryAfter := rl.window - now.Sub(entry.windowStart)
			rl.mu.Unlock()
			rl.rejectFn()(w, r, retryAfter)
			return
		}
		rl.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// cleanup evicts entries whose window has fully elapsed, once a minute, until
// its context is cancelled.
//
// The context exists so the loop has a shutdown path and so it can be tested:
// a loop that only ever returns when the process exits cannot be driven by a
// test that has to wait for every goroutine it started to finish. The
// constructors pass context.Background(), which is the previous behaviour.
func (rl *RateLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
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
}

// clientIP extracts the client IP used as the rate-limit bucket key. It
// delegates to the shared clientip.FromRequest so the limiter and the audit
// logger derive the same, non-spoofable value from proxy headers.
func clientIP(r *http.Request, trustProxy bool) string {
	return clientip.FromRequest(r, trustProxy)
}

// retryAfterSeconds rounds a wait up to whole seconds, with a floor of 1 —
// "Retry-After: 0" invites an immediate retry that is certain to fail again.
func retryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	return int(math.Max(1, math.Ceil(d.Seconds())))
}

// setRetryAfter writes the RFC 9110 §10.2.3 header telling the client when the
// window reopens.
func setRetryAfter(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(d)))
}

// NewTokenRateLimiter buckets by API token rather than by client IP.
//
// Per-IP is the wrong granularity for an API: everyone behind one CGNAT or one
// office NAT shares a bucket, so a single busy script throttles unrelated
// users, and an abusive token cannot be isolated from the address it shares.
// The token IS the identity here, so it is the right key.
//
// Mount BELOW RequireAPIToken. A request with no token falls back to its IP,
// which keeps the limiter safe if it is ever mounted above authentication.
func NewTokenRateLimiter(max int, window time.Duration, trustProxy bool) *RateLimiter {
	rl := NewProblemRateLimiter(max, window, trustProxy)
	rl.keyFn = func(r *http.Request) string {
		if t := GetAPIToken(r); t != nil {
			return "token:" + strconv.Itoa(t.ID)
		}
		return "ip:" + clientIP(r, trustProxy)
	}
	return rl
}

// NewUserRateLimiter buckets by the ACCOUNT behind an API token rather than by
// the token itself. Use it for limits that guard an expensive operation rather
// than the API surface as a whole.
//
// Per-token is the wrong granularity there: a user may hold up to
// service.MaxTokensPerUser tokens and can mint another whenever the current one
// runs out of budget, so a per-token cap on something that spends the
// operator's money is really that cap times twenty. The cost of an AI estimate
// is borne per account — the daily AI cap is per user too — so the account is
// the key that matches what is being protected.
//
// Mount BELOW RequireAPIToken. A request with no token falls back to its IP, so
// the limiter still throttles if it is ever mounted above authentication.
func NewUserRateLimiter(max int, window time.Duration, trustProxy bool) *RateLimiter {
	rl := NewProblemRateLimiter(max, window, trustProxy)
	rl.keyFn = func(r *http.Request) string {
		if t := GetAPIToken(r); t != nil {
			return "user:" + strconv.Itoa(t.UserID)
		}
		return "ip:" + clientIP(r, trustProxy)
	}
	return rl
}
