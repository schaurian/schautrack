package sse

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func newTestBroker() *Broker {
	// nil pool — tests that don't broadcast don't need DB
	return &Broker{
		clients: make(map[int]map[chan []byte]struct{}),
	}
}

func TestSubscribeUnsubscribe(t *testing.T) {
	b := newTestBroker()

	ch := b.Subscribe(1)
	if ch == nil {
		t.Fatal("Subscribe returned nil channel")
	}

	b.mu.RLock()
	if len(b.clients[1]) != 1 {
		t.Fatalf("expected 1 client, got %d", len(b.clients[1]))
	}
	b.mu.RUnlock()

	b.Unsubscribe(1, ch)

	b.mu.RLock()
	if len(b.clients[1]) != 0 {
		t.Fatalf("expected 0 clients after unsubscribe, got %d", len(b.clients[1]))
	}
	if _, exists := b.clients[1]; exists {
		t.Fatal("user entry should be removed when last client unsubscribes")
	}
	b.mu.RUnlock()
}

func TestUnsubscribeClosesChannel(t *testing.T) {
	b := newTestBroker()
	ch := b.Subscribe(1)
	b.Unsubscribe(1, ch)

	// Reading from a closed channel returns zero value immediately
	select {
	case _, open := <-ch:
		if open {
			t.Fatal("channel should be closed after Unsubscribe")
		}
	case <-time.After(time.Second):
		t.Fatal("read from closed channel should not block")
	}
}

func TestMultipleSubscribers(t *testing.T) {
	b := newTestBroker()
	ch1 := b.Subscribe(1)
	ch2 := b.Subscribe(1)
	ch3 := b.Subscribe(2)

	b.mu.RLock()
	if len(b.clients[1]) != 2 {
		t.Fatalf("expected 2 clients for user 1, got %d", len(b.clients[1]))
	}
	if len(b.clients[2]) != 1 {
		t.Fatalf("expected 1 client for user 2, got %d", len(b.clients[2]))
	}
	b.mu.RUnlock()

	// Unsubscribe one — other stays
	b.Unsubscribe(1, ch1)
	b.mu.RLock()
	if len(b.clients[1]) != 1 {
		t.Fatalf("expected 1 client for user 1 after partial unsub, got %d", len(b.clients[1]))
	}
	b.mu.RUnlock()

	b.Unsubscribe(1, ch2)
	b.Unsubscribe(2, ch3)
}

func TestSendEventDeliversMessage(t *testing.T) {
	b := newTestBroker()
	ch := b.Subscribe(1)
	defer b.Unsubscribe(1, ch)

	b.SendEvent(1, "test", map[string]string{"key": "value"})

	select {
	case msg := <-ch:
		expected := "event: test\ndata: "
		if len(msg) < len(expected) || string(msg[:len(expected)]) != expected {
			t.Fatalf("unexpected message format: %s", msg)
		}
		// Verify JSON payload is embedded
		dataStart := len("event: test\ndata: ")
		dataEnd := len(msg) - 2 // strip trailing \n\n
		var parsed map[string]string
		if err := json.Unmarshal(msg[dataStart:dataEnd], &parsed); err != nil {
			t.Fatalf("payload is not valid JSON: %v", err)
		}
		if parsed["key"] != "value" {
			t.Fatalf("expected key=value, got %v", parsed)
		}
	case <-time.After(time.Second):
		t.Fatal("expected message on channel")
	}
}

func TestSendEventOnlyTargetsCorrectUser(t *testing.T) {
	b := newTestBroker()
	ch1 := b.Subscribe(1)
	ch2 := b.Subscribe(2)
	defer b.Unsubscribe(1, ch1)
	defer b.Unsubscribe(2, ch2)

	b.SendEvent(1, "ping", map[string]any{})

	select {
	case <-ch1:
		// expected
	case <-time.After(time.Second):
		t.Fatal("user 1 should have received the message")
	}

	select {
	case <-ch2:
		t.Fatal("user 2 should NOT have received the message")
	default:
		// expected — nothing on ch2
	}
}

func TestSendEventSkipsFullChannel(t *testing.T) {
	b := newTestBroker()
	ch := b.Subscribe(1)
	defer b.Unsubscribe(1, ch)

	// Fill the channel (buffer size is 16)
	for range 16 {
		b.SendEvent(1, "fill", map[string]any{})
	}

	// This should not block even though channel is full
	done := make(chan struct{})
	go func() {
		b.SendEvent(1, "overflow", map[string]any{})
		close(done)
	}()

	select {
	case <-done:
		// expected — SendEvent returned without blocking
	case <-time.After(time.Second):
		t.Fatal("SendEvent blocked on full channel")
	}
}

func TestSendEventToNonexistentUser(t *testing.T) {
	b := newTestBroker()
	// Should not panic
	b.SendEvent(999, "noop", map[string]any{})
}

func TestConcurrentSubscribeUnsubscribeSendEvent(t *testing.T) {
	b := newTestBroker()
	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			for range iterations {
				ch := b.Subscribe(1)
				b.SendEvent(1, "ping", map[string]any{})
				b.Unsubscribe(1, ch)
			}
		}()
	}

	wg.Wait()

	b.mu.RLock()
	remaining := len(b.clients[1])
	b.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("expected 0 clients after concurrent test, got %d", remaining)
	}
}

func TestGetTargetsShortCircuitsWithNoClients(t *testing.T) {
	// The test broker has a nil pool: if getTargets reached the DB it would
	// panic. With no subscribers, it must short-circuit before the lookup.
	b := newTestBroker()
	if got := b.getTargets(1); got != nil {
		t.Fatalf("expected nil targets when no clients are connected, got %v", got)
	}
}

func TestGetTargetsUsesCacheWithoutQueryingDB(t *testing.T) {
	// nil pool: reaching the DB would panic. A subscribed client pushes
	// getTargets past the short-circuit, so a pre-seeded cache must satisfy it.
	b := newTestBroker()
	ch := b.Subscribe(1)
	defer b.Unsubscribe(1, ch)

	b.storeLinks(1, []int{2, 3})
	got := b.getTargets(1)

	if len(got) != 3 || got[0] != 1 {
		t.Fatalf("expected [1 2 3] with source first, got %v", got)
	}
	seen := map[int]bool{}
	for _, id := range got {
		seen[id] = true
	}
	if !seen[1] || !seen[2] || !seen[3] {
		t.Fatalf("expected targets to include 1,2,3; got %v", got)
	}
}

func TestGetTargetsDoesNotAliasCache(t *testing.T) {
	b := newTestBroker()
	ch := b.Subscribe(1)
	defer b.Unsubscribe(1, ch)

	b.storeLinks(1, []int{2})
	got := b.getTargets(1)
	got[len(got)-1] = 999 // mutating the returned slice must not corrupt the cache

	linked, ok := b.cachedLinks(1)
	if !ok || len(linked) != 1 || linked[0] != 2 {
		t.Fatalf("cache was mutated through the returned slice: %v", linked)
	}
}

func TestInvalidateLinksForcesRefresh(t *testing.T) {
	b := newTestBroker()
	b.storeLinks(1, []int{2})
	if _, ok := b.cachedLinks(1); !ok {
		t.Fatal("expected a fresh cache entry after storeLinks")
	}
	b.InvalidateLinks(1)
	if _, ok := b.cachedLinks(1); ok {
		t.Fatal("expected a cache miss after InvalidateLinks")
	}
}

func TestCachedLinksExpires(t *testing.T) {
	b := newTestBroker()
	b.linkCache = map[int]linkCacheEntry{
		1: {linked: []int{2}, expires: time.Now().Add(-time.Second)},
	}
	if _, ok := b.cachedLinks(1); ok {
		t.Fatal("expected an expired cache entry to miss")
	}
}

func TestServeHTTPRejectsNilContext(t *testing.T) {
	b := newTestBroker()
	req := httptest.NewRequest("GET", "/events", nil)
	// No sseUserID in context
	w := httptest.NewRecorder()

	b.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestServeHTTPRejectsWrongContextType(t *testing.T) {
	b := newTestBroker()
	req := httptest.NewRequest("GET", "/events", nil)
	ctx := context.WithValue(req.Context(), "sseUserID", "not-an-int")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	b.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}
