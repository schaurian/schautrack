package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/synctest"
	"time"
)

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	rl := &RateLimiter{
		entries:    make(map[string]*rateLimitEntry),
		max:        5,
		window:     time.Minute,
		maxEntries: defaultMaxEntries,
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 5; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i+1, w.Code, http.StatusOK)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := &RateLimiter{
		entries:    make(map[string]*rateLimitEntry),
		max:        3,
		window:     time.Minute,
		maxEntries: defaultMaxEntries,
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Make 3 requests (at the limit)
	for i := 0; i < 3; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: status = %d, want %d", i+1, w.Code, http.StatusOK)
		}
	}

	// 4th request should be blocked
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("over-limit request: status = %d, want %d", w.Code, http.StatusTooManyRequests)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["error"]; !ok {
		t.Error("expected error field in response")
	}
}

func TestRateLimiter_DifferentIPsIndependent(t *testing.T) {
	rl := &RateLimiter{
		entries:    make(map[string]*rateLimitEntry),
		max:        1,
		window:     time.Minute,
		maxEntries: defaultMaxEntries,
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First IP makes a request
	r1 := httptest.NewRequest("GET", "/", nil)
	r1.RemoteAddr = "10.0.0.1:12345"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Errorf("IP1 first request: status = %d, want %d", w1.Code, http.StatusOK)
	}

	// First IP is now rate limited
	r1b := httptest.NewRequest("GET", "/", nil)
	r1b.RemoteAddr = "10.0.0.1:12345"
	w1b := httptest.NewRecorder()
	handler.ServeHTTP(w1b, r1b)
	if w1b.Code != http.StatusTooManyRequests {
		t.Errorf("IP1 second request: status = %d, want %d", w1b.Code, http.StatusTooManyRequests)
	}

	// Second IP should still be allowed
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "10.0.0.2:12345"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("IP2 first request: status = %d, want %d", w2.Code, http.StatusOK)
	}
}

// TestRateLimiter_ResetsAfterWindow runs under synctest so it can use the real
// production window (RATE_LIMIT_AUTH defaults to 10 attempts per 15 minutes)
// instead of the 50ms stand-in it used before, and still finish instantly.
//
// That matters for more than speed. The old test slept 60ms for a 50ms window,
// which asserts "somewhere in that 10ms of slack the window reopened" — it
// could not tell a window that resets at exactly `window` from one that resets
// at `window + 9ms`, and on a loaded runner a 60ms sleep that lands late is a
// flake. With a fake clock the boundary is exact, so the two assertions below
// pin the actual contract: still blocked AT the window, open just past it.
func TestRateLimiter_ResetsAfterWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const window = 15 * time.Minute
		rl := &RateLimiter{
			entries:    make(map[string]*rateLimitEntry),
			max:        1,
			window:     window,
			maxEntries: defaultMaxEntries,
		}

		handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		do := func() int {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = "10.0.0.1:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			return w.Code
		}

		if got := do(); got != http.StatusOK {
			t.Errorf("first request: status = %d, want %d", got, http.StatusOK)
		}
		if got := do(); got != http.StatusTooManyRequests {
			t.Errorf("second request: status = %d, want %d", got, http.StatusTooManyRequests)
		}

		// The reset test is `now.Sub(windowStart) > rl.window`, strictly
		// greater — so at exactly the window boundary the caller is still
		// blocked. Asserting this direction is what stops the comparison being
		// silently loosened to >=, which would let a caller through a full
		// window early on every cycle.
		time.Sleep(window)
		if got := do(); got != http.StatusTooManyRequests {
			t.Errorf("at exactly the window boundary: status = %d, want %d — the window reopened early",
				got, http.StatusTooManyRequests)
		}

		// One nanosecond past it, the window is genuinely over. A fake clock
		// makes a one-nanosecond assertion meaningful; a real one could not
		// resolve it.
		time.Sleep(time.Nanosecond)
		if got := do(); got != http.StatusOK {
			t.Errorf("just past the window: status = %d, want %d — the window never reopened",
				got, http.StatusOK)
		}
	})
}

// TestRateLimiterCleanupEvictsElapsedEntries covers the eviction loop, which
// had no test before: it is a bare `for range ticker.C` on a one-minute
// ticker, so driving even a single iteration meant a one-minute test.
//
// It is the only thing bounding the limiter's memory below maxEntries. If it
// stopped running, entries would accumulate one per unique client IP until the
// 10k cap, at which point NewRateLimiter starts rejecting *unseen* IPs
// outright — a slow drift into refusing legitimate traffic that no
// single-request test would notice.
func TestRateLimiterCleanupEvictsElapsedEntries(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const window = 15 * time.Minute
		rl := &RateLimiter{
			entries:    make(map[string]*rateLimitEntry),
			max:        1,
			window:     window,
			maxEntries: defaultMaxEntries,
		}

		go rl.cleanup(t.Context())

		handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.0.0.1:12345"
		handler.ServeHTTP(httptest.NewRecorder(), r)

		entries := func() int {
			rl.mu.Lock()
			defer rl.mu.Unlock()
			return len(rl.entries)
		}

		if got := entries(); got != 1 {
			t.Fatalf("tracked entries after one request = %d, want 1", got)
		}

		// A tick while the entry's window is still open must not evict it —
		// otherwise the limiter would forget callers mid-window and the cap
		// would not hold.
		time.Sleep(time.Minute)
		synctest.Wait()
		if got := entries(); got != 1 {
			t.Fatalf("entry evicted while its window was still open: %d entries, want 1", got)
		}

		// Once the window has fully elapsed, the next tick must drop it.
		time.Sleep(window)
		synctest.Wait()
		if got := entries(); got != 0 {
			t.Fatalf("entry survived %v past its window: %d entries, want 0 — "+
				"the map grows without bound if eviction stops", window, got)
		}
	})
}

func TestRateLimiter_XForwardedFor(t *testing.T) {
	rl := &RateLimiter{
		entries:    make(map[string]*rateLimitEntry),
		max:        1,
		window:     time.Minute,
		maxEntries: defaultMaxEntries,
		trustProxy: true,
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request with X-Forwarded-For
	r1 := httptest.NewRequest("GET", "/", nil)
	r1.RemoteAddr = "127.0.0.1:12345"
	r1.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.1")
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Errorf("first request: status = %d, want %d", w1.Code, http.StatusOK)
	}

	// Same X-Forwarded-For should be rate limited
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "127.0.0.1:12345"
	r2.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.1")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request from same XFF: status = %d, want %d", w2.Code, http.StatusTooManyRequests)
	}
}

func TestRateLimiter_MaxEntriesCap(t *testing.T) {
	rl := &RateLimiter{
		entries:    make(map[string]*rateLimitEntry),
		max:        100,
		window:     time.Minute,
		maxEntries: 2, // very low cap
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Fill up the entries
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "10.0.0." + string(rune('1'+i)) + ":12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
	}

	// New IP should be rejected when entries map is full
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.99:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("over-cap request: status = %d, want %d", w.Code, http.StatusTooManyRequests)
	}
}

func TestClientIP_TrustProxy(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		want       string
	}{
		{"remote addr only", "192.168.1.1:1234", "", "", "192.168.1.1"},
		{"x-forwarded-for single", "127.0.0.1:1234", "10.0.0.1", "", "10.0.0.1"},
		// Rightmost (proxy-appended) entry wins; the leftmost is client-supplied.
		{"x-forwarded-for multiple", "127.0.0.1:1234", "10.0.0.1, 10.0.0.2", "", "10.0.0.2"},
		{"spoofed leftmost cannot change the key", "127.0.0.1:1234", "6.6.6.6, 10.0.0.2", "", "10.0.0.2"},
		{"x-real-ip", "127.0.0.1:1234", "", "10.0.0.5", "10.0.0.5"},
		{"xff takes precedence over xri", "127.0.0.1:1234", "10.0.0.1", "10.0.0.5", "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				r.Header.Set("X-Real-Ip", tt.xri)
			}

			got := clientIP(r, true)
			if got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientIP_NoTrustProxy(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		want       string
	}{
		{"ignores xff", "192.168.1.1:1234", "10.0.0.1", "", "192.168.1.1"},
		{"ignores xri", "192.168.1.1:1234", "", "10.0.0.5", "192.168.1.1"},
		{"ignores both", "192.168.1.1:1234", "10.0.0.1", "10.0.0.5", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				r.Header.Set("X-Real-Ip", tt.xri)
			}

			got := clientIP(r, false)
			if got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
