package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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

func TestRateLimiter_ResetsAfterWindow(t *testing.T) {
	rl := &RateLimiter{
		entries:    make(map[string]*rateLimitEntry),
		max:        1,
		window:     50 * time.Millisecond,
		maxEntries: defaultMaxEntries,
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request succeeds
	r1 := httptest.NewRequest("GET", "/", nil)
	r1.RemoteAddr = "10.0.0.1:12345"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, r1)
	if w1.Code != http.StatusOK {
		t.Errorf("first request: status = %d, want %d", w1.Code, http.StatusOK)
	}

	// Second request is blocked
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "10.0.0.1:12345"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, r2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: status = %d, want %d", w2.Code, http.StatusTooManyRequests)
	}

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	// Third request should succeed (window reset)
	r3 := httptest.NewRequest("GET", "/", nil)
	r3.RemoteAddr = "10.0.0.1:12345"
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, r3)
	if w3.Code != http.StatusOK {
		t.Errorf("post-window request: status = %d, want %d", w3.Code, http.StatusOK)
	}
}

func TestRateLimiter_XForwardedFor(t *testing.T) {
	rl := &RateLimiter{
		entries:    make(map[string]*rateLimitEntry),
		max:        1,
		window:     time.Minute,
		maxEntries: defaultMaxEntries,
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

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		want       string
	}{
		{"remote addr only", "192.168.1.1:1234", "", "", "192.168.1.1"},
		{"x-forwarded-for single", "127.0.0.1:1234", "10.0.0.1", "", "10.0.0.1"},
		{"x-forwarded-for multiple", "127.0.0.1:1234", "10.0.0.1, 10.0.0.2", "", "10.0.0.1"},
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

			got := clientIP(r)
			if got != tt.want {
				t.Errorf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
