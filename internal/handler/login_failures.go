package handler

import (
	"sync"
	"time"

	"schautrack/internal/session"
)

// loginCaptchaThreshold is the failed-attempt count (per session, per account
// email, or per client IP) at which login requires solving a captcha.
const loginCaptchaThreshold = 3

// loginFailureWindow is how long server-side failure counters persist. It
// matches the auth rate limiter's window so both defenses decay together.
const loginFailureWindow = 15 * time.Minute

// maxTrackedLoginKeys bounds the tracker's memory (same cap as the rate
// limiter): beyond it, new keys are not tracked rather than growing the map.
const maxTrackedLoginKeys = 10000

// loginFailures tracks failed login attempts server-side, keyed by account
// email ("email:<addr>") and proxy-validated client IP ("ip:<addr>"). The
// session-based counter alone is client-controlled: a client that drops its
// cookies starts every request with loginFailedAttempts=0 and never triggers
// the captcha. These counters close that hole.
var loginFailures = newFailureTracker(loginFailureWindow, maxTrackedLoginKeys)

// failureTracker is a bounded, concurrency-safe in-memory failure counter
// with a fixed window per key (mirrors internal/middleware/ratelimit.go).
type failureTracker struct {
	mu         sync.Mutex
	entries    map[string]*failureEntry
	window     time.Duration
	maxEntries int
	now        func() time.Time // injectable for tests
}

type failureEntry struct {
	count       int
	windowStart time.Time
}

func newFailureTracker(window time.Duration, maxEntries int) *failureTracker {
	return &failureTracker{
		entries:    make(map[string]*failureEntry),
		window:     window,
		maxEntries: maxEntries,
		now:        time.Now,
	}
}

// Record increments the failure count for key. The count resets once the
// window since the first recorded failure elapses. At capacity, expired
// entries are pruned first; if the map is still full, new keys are dropped
// (fail open — the session counter and IP rate limiter still apply) so
// memory stays bounded even under key-spraying.
func (t *failureTracker) Record(key string) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()

	if e, ok := t.entries[key]; ok {
		if now.Sub(e.windowStart) > t.window {
			e.count = 0
			e.windowStart = now
		}
		e.count++
		return
	}
	if len(t.entries) >= t.maxEntries {
		t.pruneLocked(now)
		if len(t.entries) >= t.maxEntries {
			return
		}
	}
	t.entries[key] = &failureEntry{count: 1, windowStart: now}
}

// Count returns the failures recorded for key within the current window.
func (t *failureTracker) Count(key string) int {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[key]
	if !ok {
		return 0
	}
	if now.Sub(e.windowStart) > t.window {
		delete(t.entries, key)
		return 0
	}
	return e.count
}

// Reset forgets all failures for key (called after a successful login).
func (t *failureTracker) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

func (t *failureTracker) pruneLocked(now time.Time) {
	for k, e := range t.entries {
		if now.Sub(e.windowStart) > t.window {
			delete(t.entries, k)
		}
	}
}

// recordServerLoginFailure counts a failed login against the account email
// and the client IP, independent of the (client-controlled) session.
func recordServerLoginFailure(email, ip string) {
	if email != "" {
		loginFailures.Record("email:" + email)
	}
	if ip != "" {
		loginFailures.Record("ip:" + ip)
	}
}

// clearLoginFailures resets all failure counters after a successful login.
func clearLoginFailures(sess *session.Session, email, ip string) {
	sess.Delete("loginFailedAttempts")
	if email != "" {
		loginFailures.Reset("email:" + email)
	}
	if ip != "" {
		loginFailures.Reset("ip:" + ip)
	}
}

// loginCaptchaRequired reports whether a login attempt for this
// session/email/IP must solve a captcha: any of the three counters reaching
// loginCaptchaThreshold triggers it.
func loginCaptchaRequired(sess *session.Session, email, ip string) bool {
	if attempts, _ := sess.GetInt("loginFailedAttempts"); attempts >= loginCaptchaThreshold {
		return true
	}
	return loginFailures.Count("email:"+email) >= loginCaptchaThreshold ||
		loginFailures.Count("ip:"+ip) >= loginCaptchaThreshold
}
