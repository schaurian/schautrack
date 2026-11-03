package sse

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"schautrack/internal/database"
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

// TestListenerClearsOnlyOnceListening pins the ORDER in listenOnce: LISTEN
// first, then clear. Cleared the other way round, a lookup that refills the
// cache in the gap and an invalidation sent in the same gap are both possible,
// and the invalidation is lost — the stale entry then lives for the TTL.
//
// The hook does exactly that the moment the cache is cleared: refill user 1,
// then publish an invalidation for user 1 and a sentinel. Only an instance
// already listening hears them; the sentinel arriving proves the invalidation
// before it was processed too.
func TestListenerClearsOnlyOnceListening(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pub, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pub.Close(context.Background())

	b := newTestBroker()
	sentinel := b.Subscribe(9)
	defer b.Unsubscribe(9, sentinel)
	hookErr := make(chan error, 1)
	b.afterCacheClear = func() {
		_, stamp, _ := b.cachedLinks(1)
		b.storeLinks(1, stamp, []linkTarget{{userID: 2, shares: allShared}})
		inv, _ := json.Marshal(envelope{Invalidate: []int{1}})
		ev, _ := json.Marshal(envelope{UserID: 9, Event: "sentinel", Data: json.RawMessage(`{}`)})
		for _, m := range [][]byte{inv, ev} {
			if _, err := pub.Exec(ctx, "SELECT pg_notify($1, $2)", notifyChannel, string(m)); err != nil {
				hookErr <- err
				return
			}
		}
		hookErr <- nil
	}

	go b.listenOnce(ctx, url)
	if err := <-hookErr; err != nil {
		t.Fatalf("publishing from the hook: %v", err)
	}
	select {
	case <-sentinel:
	case <-time.After(5 * time.Second):
		t.Fatal("notifications sent right after the clear were never heard: the cache was cleared before LISTEN")
	}
	if linked, _, ok := b.cachedLinks(1); ok {
		t.Fatalf("an entry invalidated right after the clear survived: %v", linked)
	}
}

// TestInvalidationChunksFitNotify checks the splitter on its own: every chunk
// fits a NOTIFY payload and together they are exactly the input, in order.
func TestInvalidationChunksFitNotify(t *testing.T) {
	ids := make([]int, 0, 3000)
	for i := range 3000 {
		ids = append(ids, -2_000_000_000+i) // widest ints the ids could plausibly be
	}
	var joined []int
	chunks := invalidationChunks(ids)
	if len(chunks) < 2 {
		t.Fatalf("3000 ids fit one chunk? got %d chunks", len(chunks))
	}
	for i, c := range chunks {
		msg, err := json.Marshal(envelope{Invalidate: c})
		if err != nil || len(msg) > pgNotifyMaxPayload {
			t.Errorf("chunk %d: %d bytes (limit %d), err %v", i, len(msg), pgNotifyMaxPayload, err)
		}
		joined = append(joined, c...)
	}
	if len(joined) != len(ids) {
		t.Fatalf("chunks hold %d ids, want %d", len(joined), len(ids))
	}
	for i := range ids {
		if joined[i] != ids[i] {
			t.Fatalf("id %d: got %d, want %d", i, joined[i], ids[i])
		}
	}
}

// TestLargeInvalidationReachesOtherInstances: over 1000 ids — what one reaper
// pass can produce — is far past NOTIFY's 8000-byte cap as one message. All of
// them must still be dropped on another instance.
func TestLargeInvalidationReachesOtherInstances(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	writer := &Broker{clients: make(map[int]map[chan []byte]struct{}), pool: pool}

	other := newTestBroker()
	listening := make(chan struct{})
	other.afterCacheClear = func() { close(listening) }
	sentinel := other.Subscribe(9)
	defer other.Unsubscribe(9, sentinel)
	go other.listenOnce(ctx, url)
	select {
	case <-listening:
	case <-time.After(10 * time.Second):
		t.Fatal("listener never connected")
	}

	ids := make([]int, 0, 2000)
	for i := range 2000 {
		ids = append(ids, 1_000_000+i)
	}
	other.linkMu.Lock()
	for _, id := range ids {
		other.linkCache[id] = linkCacheEntry{linked: []linkTarget{{userID: 2, shares: allShared}}, expires: time.Now().Add(time.Hour)}
	}
	other.linkMu.Unlock()

	writer.InvalidateLinks(ids...)
	writer.SendEvent(9, "sentinel", map[string]any{})
	select {
	case <-sentinel:
	case <-time.After(10 * time.Second):
		t.Fatal("sentinel never arrived")
	}
	survivors := 0
	for _, id := range ids {
		if _, _, ok := other.cachedLinks(id); ok {
			survivors++
		}
	}
	if survivors != 0 {
		t.Fatalf("%d of %d invalidated ids are still cached on the other instance", survivors, len(ids))
	}
}
