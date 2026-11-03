package sse

import (
	"context"
	"os"
	"testing"
	"time"

	"schautrack/internal/service"
)

// TestLookupRacingAnInvalidationDoesNotRefillTheCache pins the generation
// fence. A cache miss reads the links; before it stores them, the link is
// revoked and the cache invalidated. Storing what was read would put the
// pre-revoke set back for the whole TTL. The lookup is held mid-query by the
// loadLinks seam so the interleaving is exact rather than timing-dependent.
func TestLookupRacingAnInvalidationDoesNotRefillTheCache(t *testing.T) {
	b := newTestBroker()
	started, release := make(chan struct{}), make(chan struct{})
	b.loadLinks = func(ctx context.Context, userID int) ([]linkTarget, error) {
		close(started)
		<-release
		return []linkTarget{{userID: 2, shares: allShared}}, nil // read before the revoke
	}

	done := make(chan []int)
	go func() { done <- b.getTargets(1, service.ShareNutrition) }()

	<-started
	b.invalidateLocal(1) // the revoke commits and its invalidation lands mid-query
	close(release)
	<-done

	if linked, _, ok := b.cachedLinks(1); ok {
		t.Fatalf("a lookup that started before the invalidation was cached: %v", linked)
	}
}

// TestLookupRacingAFullClearDoesNotRefillTheCache is the same race against
// clearLinkCache (listener reconnect), which fences with the epoch.
func TestLookupRacingAFullClearDoesNotRefillTheCache(t *testing.T) {
	b := newTestBroker()
	started, release := make(chan struct{}), make(chan struct{})
	b.loadLinks = func(ctx context.Context, userID int) ([]linkTarget, error) {
		close(started)
		<-release
		return []linkTarget{{userID: 2, shares: allShared}}, nil
	}
	done := make(chan []int)
	go func() { done <- b.getTargets(1, service.ShareNutrition) }()

	<-started
	b.clearLinkCache()
	close(release)
	<-done

	if linked, _, ok := b.cachedLinks(1); ok {
		t.Fatalf("a lookup that started before the clear was cached: %v", linked)
	}
}

// TestUndisturbedLookupIsCached keeps the fence from being "fixed" by never
// caching at all.
func TestUndisturbedLookupIsCached(t *testing.T) {
	b := newTestBroker()
	b.loadLinks = func(ctx context.Context, userID int) ([]linkTarget, error) {
		return []linkTarget{{userID: 2, shares: allShared}}, nil
	}
	b.getTargets(1, service.ShareNutrition)
	if _, _, ok := b.cachedLinks(1); !ok {
		t.Fatal("an undisturbed lookup was not cached")
	}
}

// TestListenerConnectClearsTheLinkCache pins that (re)connecting the listener
// drops every cached link set. Invalidations published while an instance was
// not listening never reach it, so whatever it cached before the gap may be
// stale in ways no later message will correct.
func TestListenerConnectClearsTheLinkCache(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	b := newTestBroker()
	// An entry that outlives the test, so only a clear can remove it — not
	// the TTL running out while the listener connects.
	b.linkCache = map[int]linkCacheEntry{
		1: {linked: []linkTarget{{userID: 2, shares: allShared}}, expires: time.Now().Add(time.Hour)},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- b.listenOnce(ctx, url) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, _, ok := b.cachedLinks(1); !ok {
			return
		}
		select {
		case err := <-errc:
			t.Fatalf("listenOnce returned before clearing the cache: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the link cache survived the listener connecting")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
