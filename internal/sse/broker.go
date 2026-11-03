package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/service"
)

// linkTarget is one accepted link of a source user: the friend's ID and what
// the SOURCE shares toward that friend (service.LinkUser.SharesWithThem).
type linkTarget struct {
	userID int
	shares map[string]bool
}

// linkCacheEntry holds a resolved set of accepted links for one source user
// together with its expiry.
type linkCacheEntry struct {
	linked  []linkTarget
	expires time.Time
}

// Broker manages SSE connections per user.
type Broker struct {
	mu      sync.RWMutex
	clients map[int]map[chan []byte]struct{}
	pool    *pgxpool.Pool

	// linkMu guards linkCache, a short-TTL cache of each user's accepted-link
	// target IDs so a burst of broadcasts does not repeat the same DB lookup,
	// and the two counters that keep a lookup racing an invalidation from
	// refilling the cache with what it read before the change: linkGen is
	// bumped per user by invalidateLocal, linkEpoch by clearLinkCache.
	linkMu    sync.Mutex
	linkCache map[int]linkCacheEntry
	linkGen   map[int]uint64
	linkEpoch uint64

	// loadLinks resolves a user's accepted links; nil means the database.
	// A seam for tests that need to interleave a lookup with an invalidation.
	loadLinks func(ctx context.Context, userID int) ([]linkTarget, error)
}

// linkStamp is the cache version a lookup started from. storeLinks only keeps
// the result if neither the user's generation nor the epoch moved meanwhile.
type linkStamp struct {
	gen, epoch uint64
}

func NewBroker(pool *pgxpool.Pool) *Broker {
	b := &Broker{
		clients:   make(map[int]map[chan []byte]struct{}),
		pool:      pool,
		linkCache: make(map[int]linkCacheEntry),
	}
	go b.cleanupLoop()
	return b
}

func (b *Broker) Subscribe(userID int) chan []byte {
	ch := make(chan []byte, 16)
	b.mu.Lock()
	if b.clients[userID] == nil {
		b.clients[userID] = make(map[chan []byte]struct{})
	}
	b.clients[userID][ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *Broker) Unsubscribe(userID int, ch chan []byte) {
	b.mu.Lock()
	if set, ok := b.clients[userID]; ok {
		delete(set, ch)
		if len(set) == 0 {
			delete(b.clients, userID)
		}
	}
	b.mu.Unlock()
	close(ch)
}

// notifyChannel is the Postgres LISTEN/NOTIFY channel every instance uses to
// fan events out to its own subscribers.
const notifyChannel = "schautrack_events"

// pgNotifyMaxPayload is Postgres' hard limit for a NOTIFY payload (8000 bytes).
const pgNotifyMaxPayload = 8000

// envelope is one event addressed to one user, as it travels through Postgres.
//
// An envelope with Invalidate set is not an event but a link-cache
// invalidation for those users, so a share revoked on one instance stops
// activity events from every instance, not just after the cache TTL elsewhere.
// (An instance predating the field reads it as an event for user 0, which has
// no subscribers.)
type envelope struct {
	UserID     int             `json:"u"`
	Event      string          `json:"e"`
	Data       json.RawMessage `json:"d"`
	Invalidate []int           `json:"i,omitempty"`
}

// SendEvent delivers an event to every connection of one user — including the
// ones held by *other* instances.
//
// A subscriber's channel lives in the memory of whichever instance is serving
// its SSE stream, while the write that triggers the event can land on any
// instance. So events are published through Postgres NOTIFY and delivered by
// each instance's listener (including this one's), rather than written straight
// to the local map. Publishing locally instead would mean a user only sees
// realtime updates when their write happens to hit the same pod that holds
// their stream.
func (b *Broker) SendEvent(userID int, eventName string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}

	if b.pool == nil {
		// No database to publish through (tests, and any future in-process use).
		b.deliverLocal(userID, eventName, data)
		return
	}

	msg, err := json.Marshal(envelope{UserID: userID, Event: eventName, Data: data})
	if err != nil || len(msg) > pgNotifyMaxPayload {
		// Oversized or unmarshalable: still serve the connections we hold, so
		// a single-instance deployment degrades to exactly the old behaviour.
		slog.Warn("sse: publishing locally only", "event", eventName, "bytes", len(msg), "error", err)
		b.deliverLocal(userID, eventName, data)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := b.pool.Exec(ctx, "SELECT pg_notify($1, $2)", notifyChannel, string(msg)); err != nil {
		// Postgres unreachable — local delivery is better than none.
		slog.Error("sse: pg_notify failed, delivering locally only", "event", eventName, "error", err)
		b.deliverLocal(userID, eventName, data)
	}
}

// deliverLocal writes an event to the subscribers this instance holds.
func (b *Broker) deliverLocal(userID int, eventName string, data []byte) {
	msg := fmt.Appendf(nil, "event: %s\ndata: %s\n\n", eventName, data)

	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients[userID] {
		select {
		case ch <- msg:
		default:
			// Channel full, skip
		}
	}
}

// Listen consumes the NOTIFY channel for the lifetime of ctx and hands each
// event to this instance's subscribers. It reconnects with backoff, and uses
// its own connection rather than one from the shared pool — a LISTEN occupies
// its connection permanently, and the pool is sized for request traffic.
func (b *Broker) Listen(ctx context.Context, dsn string) {
	backoff := time.Second
	for {
		if err := b.listenOnce(ctx, dsn); err != nil && ctx.Err() == nil {
			slog.Error("sse: listener connection lost", "error", err, "retry_in", backoff)
		}
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (b *Broker) listenOnce(ctx context.Context, dsn string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())

	if _, err := conn.Exec(ctx, "LISTEN "+notifyChannel); err != nil {
		return err
	}
	// Invalidations published while this instance was not listening — before
	// the first connect, or during a reconnect gap — are lost, so nothing in
	// the cache can be trusted any more. Cleared only now that LISTEN is in
	// place: every invalidation from here on will be heard.
	b.clearLinkCache()
	slog.Info("sse: listening for cross-instance events", "channel", notifyChannel)

	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		b.handleNotification(n.Payload)
	}
}

// handleNotification applies one message heard on notifyChannel: a link-cache
// invalidation, or an event for this instance's subscribers.
func (b *Broker) handleNotification(payload string) {
	var env envelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		slog.Error("sse: dropping malformed event", "error", err)
		return
	}
	if len(env.Invalidate) > 0 {
		b.invalidateLocal(env.Invalidate...)
		return
	}
	b.deliverLocal(env.UserID, env.Event, env.Data)
}

// The activity broadcasts below reach the source user and only those linked
// friends the source shares the matching category with. An event carries no
// data, but its arrival alone tells the receiver "they just logged a meal /
// weighed in / edited a note" — so a friend who cannot see that category must
// not get it either. Same reasoning as BroadcastSavedFoodChange.

// BroadcastEntryChange announces a change to calorie entries or to the daily
// budget (planner) — the nutrition category.
func (b *Broker) BroadcastEntryChange(sourceUserID int) {
	b.broadcastActivity(sourceUserID, "entry-change", service.ShareNutrition)
}

// BroadcastWeightChange announces a weight change. The event name stays
// "entry-change": the client refetches weight on it.
func (b *Broker) BroadcastWeightChange(sourceUserID int) {
	b.broadcastActivity(sourceUserID, "entry-change", service.ShareWeight)
}

func (b *Broker) BroadcastTodoChange(sourceUserID int) {
	b.broadcastActivity(sourceUserID, "todo-change", service.ShareTodos)
}

func (b *Broker) BroadcastNoteChange(sourceUserID int) {
	b.broadcastActivity(sourceUserID, "note-change", service.ShareNotes)
}

func (b *Broker) broadcastActivity(sourceUserID int, event, category string) {
	payload := map[string]any{"sourceUserId": sourceUserID, "at": time.Now().UnixMilli()}
	for _, id := range b.getTargets(sourceUserID, category) {
		b.SendEvent(id, event, payload)
	}
}

// BroadcastSavedFoodChange notifies the owner and only those linked friends the
// owner shares quick-adds with: a friend who is not shared savedfoods has
// nothing to refetch, so an event to them is both wasted work and an activity
// oracle.
func (b *Broker) BroadcastSavedFoodChange(sourceUserID int) {
	b.broadcastActivity(sourceUserID, "saved-food-change", service.ShareSavedFoods)
}

func (b *Broker) BroadcastSettingsChange(userID int, settings any) {
	b.SendEvent(userID, "settings-change", settings)
}

func (b *Broker) BroadcastLinkChange(targetUserID int, linkType string, detail map[string]any) {
	payload := map[string]any{"type": linkType}
	for k, v := range detail {
		payload[k] = v
	}
	b.SendEvent(targetUserID, "link-change", payload)
}

func (b *Broker) BroadcastLinkLabelChange(linkID, userID int, label string) {
	b.SendEvent(userID, "link-label-change", map[string]any{
		"linkId": linkID, "label": label,
	})
}

func (b *Broker) BroadcastLinkSharesChange(linkID, userID int, shares map[string]bool) {
	b.SendEvent(userID, "link-shares-change", map[string]any{
		"linkId": linkID, "shares": shares,
	})
}

// userIDKey is the context key carrying the authenticated user ID into
// ServeHTTP. It is an unexported zero-width struct type rather than a string:
// a bare string key lives in the same namespace as every other package's
// string keys, so any dependency storing "sseUserID" — for its own unrelated
// purpose — would silently satisfy the type assertion below and hand this
// handler someone else's user ID. A private type cannot collide by
// construction.
type userIDKey struct{}

// WithUserID returns a context carrying the user ID that ServeHTTP will stream
// events for. Callers must use this rather than setting the key themselves,
// which is the point of keeping the key type unexported.
func WithUserID(ctx context.Context, userID int) context.Context {
	return context.WithValue(ctx, userIDKey{}, userID)
}

// ServeHTTP is the SSE endpoint handler.
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by auth middleware)
	userID, ok := r.Context().Value(userIDKey{}).(int)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	// Clear the write deadline for this long-lived stream. The server sets a
	// 60s WriteTimeout to blunt slow clients on ordinary responses, but that is
	// a single absolute deadline for the whole response — net/http never
	// refreshes it per write. Left in place it would force-close every SSE
	// stream after ~60s, causing needless reconnect churn (each reconnect costs
	// a session load + full user SELECT) and dropping any events broadcast
	// during the reconnect gap. NewResponseController reaches the underlying
	// net/http conn through the session middleware's deferredSaveWriter.Unwrap().
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Time{}); err != nil {
		slog.Warn("failed to clear SSE write deadline", "error", err)
	}

	ch := b.Subscribe(userID)
	defer func() {
		b.Unsubscribe(userID, ch)
	}()

	// Send ready event
	fmt.Fprint(w, "event: ready\ndata: {}\n\n")
	flusher.Flush()

	// Keepalive ticker
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, open := <-ch:
			if !open {
				return
			}
			w.Write(msg)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprint(w, "event: ping\ndata: {}\n\n")
			flusher.Flush()
		}
	}
}

// linkCacheTTL bounds how long a resolved accepted-links set is reused between
// broadcasts. It absorbs bursts of rapid mutations — which would otherwise each
// issue an identical link lookup — and is the upper bound on staleness:
// InvalidateLinks reaches other instances only as fast as their listeners
// hear it, and not at all while one is disconnected (the cache is cleared when
// it reconnects, but a lookup during the gap can still be stale until then).
const linkCacheTTL = 5 * time.Second

// getTargets returns the source user followed by every linked friend the
// source shares category with.
func (b *Broker) getTargets(sourceUserID int, category string) []int {
	// This used to return early when *this* instance held no subscribers, on
	// the reasoning that an event with nobody to deliver it to is waste. That
	// only holds for a single instance: behind a load balancer the pod handling
	// a write is usually not the pod holding the user's stream, so the check
	// fired exactly when the event was needed and nothing was ever published.
	// Resolving targets is cheap — the link set is cached below, and publishing
	// is one pg_notify.
	linked, stamp, ok := b.cachedLinks(sourceUserID)
	if !ok {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var err error
		linked, err = b.lookupLinks(ctx, sourceUserID)
		if err != nil {
			// Don't cache failures — fall back to just the source user.
			slog.Error("failed to load linked users for broadcast", "error", err)
			return []int{sourceUserID}
		}
		b.storeLinks(sourceUserID, stamp, linked)
	}
	targets := []int{sourceUserID}
	for _, l := range linked {
		if l.shares[category] {
			targets = append(targets, l.userID)
		}
	}
	return targets
}

func (b *Broker) lookupLinks(ctx context.Context, userID int) ([]linkTarget, error) {
	if b.loadLinks != nil {
		return b.loadLinks(ctx, userID)
	}
	links, err := service.GetAcceptedLinkUsers(ctx, b.pool, userID)
	if err != nil {
		return nil, err
	}
	linked := make([]linkTarget, 0, len(links))
	for _, link := range links {
		linked = append(linked, linkTarget{userID: link.UserID, shares: link.SharesWithThem})
	}
	return linked, nil
}

// cachedLinks returns the cached accepted links for userID when a fresh entry
// exists, and otherwise the stamp a lookup must hand to storeLinks. The
// returned slice is owned by the cache and must not be mutated by callers
// (getTargets only reads it).
func (b *Broker) cachedLinks(userID int) ([]linkTarget, linkStamp, bool) {
	b.linkMu.Lock()
	defer b.linkMu.Unlock()
	stamp := linkStamp{gen: b.linkGen[userID], epoch: b.linkEpoch}
	entry, ok := b.linkCache[userID]
	if !ok || time.Now().After(entry.expires) {
		return nil, stamp, false
	}
	return entry.linked, stamp, true
}

// storeLinks caches linked for userID — unless an invalidation for that user,
// or a full clear, happened since stamp was taken. A lookup that read the
// links just before a revoke committed would otherwise write the old set back
// after the invalidation dropped it, and serve it for the whole TTL.
func (b *Broker) storeLinks(userID int, stamp linkStamp, linked []linkTarget) {
	b.linkMu.Lock()
	defer b.linkMu.Unlock()
	if b.linkGen[userID] != stamp.gen || b.linkEpoch != stamp.epoch {
		return
	}
	if b.linkCache == nil {
		b.linkCache = make(map[int]linkCacheEntry)
	}
	b.linkCache[userID] = linkCacheEntry{linked: linked, expires: time.Now().Add(linkCacheTTL)}
}

// InvalidateLinks drops any cached accepted-links set for the given users so the
// next broadcast re-resolves it from the database. Callers in the link handlers
// invoke this whenever a user's set of accepted links or their shares change.
//
// This instance forgets at once; every other instance forgets when its
// listener hears the published invalidation, which arrives through the same
// ordered channel as events. That shortens staleness elsewhere to the
// listener's lag; it does not remove it. A failed publish, or a listener that
// is disconnected when the invalidation goes out, leaves the old set in place
// until linkCacheTTL (or, for the disconnected one, until it reconnects and
// clears its whole cache).
func (b *Broker) InvalidateLinks(userIDs ...int) {
	b.invalidateLocal(userIDs...)
	if b.pool == nil || len(userIDs) == 0 {
		return
	}
	msg, err := json.Marshal(envelope{Invalidate: userIDs})
	if err != nil || len(msg) > pgNotifyMaxPayload {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := b.pool.Exec(ctx, "SELECT pg_notify($1, $2)", notifyChannel, string(msg)); err != nil {
		slog.Error("sse: could not publish link-cache invalidation", "error", err)
	}
}

func (b *Broker) invalidateLocal(userIDs ...int) {
	b.linkMu.Lock()
	defer b.linkMu.Unlock()
	if b.linkGen == nil {
		b.linkGen = make(map[int]uint64)
	}
	for _, id := range userIDs {
		delete(b.linkCache, id)
		b.linkGen[id]++
	}
}

// clearLinkCache drops every cached link set and fences off lookups already in
// flight. The per-user generations are reset with it: the epoch bump alone
// already rejects every stamp taken before this point, and starting the map
// over keeps it from growing with every user ever invalidated.
func (b *Broker) clearLinkCache() {
	b.linkMu.Lock()
	defer b.linkMu.Unlock()
	b.linkCache = make(map[int]linkCacheEntry)
	b.linkGen = make(map[int]uint64)
	b.linkEpoch++
}

func (b *Broker) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		// Copy user IDs while holding lock, then send outside lock
		// to avoid deadlock (SendEvent also acquires RLock).
		b.mu.RLock()
		userIDs := make([]int, 0, len(b.clients))
		for userID := range b.clients {
			userIDs = append(userIDs, userID)
		}
		b.mu.RUnlock()
		for _, userID := range userIDs {
			b.SendEvent(userID, "cleanup-ping", map[string]any{})
		}
	}
}
