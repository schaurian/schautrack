package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/service"
)

// linkCacheEntry holds a resolved set of accepted-link user IDs for one source
// user together with its expiry.
type linkCacheEntry struct {
	linked  []int
	expires time.Time
}

// Broker manages SSE connections per user.
type Broker struct {
	mu      sync.RWMutex
	clients map[int]map[chan []byte]struct{}
	pool    *pgxpool.Pool

	// linkMu guards linkCache, a short-TTL cache of each user's accepted-link
	// target IDs so a burst of broadcasts does not repeat the same DB lookup.
	linkMu    sync.Mutex
	linkCache map[int]linkCacheEntry
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

func (b *Broker) SendEvent(userID int, eventName string, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
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

func (b *Broker) BroadcastEntryChange(sourceUserID int) {
	targets := b.getTargets(sourceUserID)
	payload := map[string]any{"sourceUserId": sourceUserID, "at": time.Now().UnixMilli()}
	for _, id := range targets {
		b.SendEvent(id, "entry-change", payload)
	}
}

func (b *Broker) BroadcastTodoChange(sourceUserID int) {
	targets := b.getTargets(sourceUserID)
	payload := map[string]any{"sourceUserId": sourceUserID, "at": time.Now().UnixMilli()}
	for _, id := range targets {
		b.SendEvent(id, "todo-change", payload)
	}
}

func (b *Broker) BroadcastSavedFoodChange(sourceUserID int) {
	targets := b.getTargets(sourceUserID)
	payload := map[string]any{"sourceUserId": sourceUserID, "at": time.Now().UnixMilli()}
	for _, id := range targets {
		b.SendEvent(id, "saved-food-change", payload)
	}
}

func (b *Broker) BroadcastNoteChange(sourceUserID int) {
	targets := b.getTargets(sourceUserID)
	payload := map[string]any{"sourceUserId": sourceUserID, "at": time.Now().UnixMilli()}
	for _, id := range targets {
		b.SendEvent(id, "note-change", payload)
	}
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

// ServeHTTP is the SSE endpoint handler.
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by auth middleware)
	userID, ok := r.Context().Value("sseUserID").(int)
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
// issue an identical link lookup — while keeping staleness small even if an
// explicit invalidation were ever missed. Link accept/remove call
// InvalidateLinks, so newly (un)linked users take effect immediately.
const linkCacheTTL = 5 * time.Second

func (b *Broker) getTargets(sourceUserID int) []int {
	// If nobody at all is connected, no event can be delivered to any user, so
	// resolving link targets would be pure waste — e.g. mutations from the
	// mobile app or API while no dashboard is open.
	b.mu.RLock()
	anyClients := len(b.clients) > 0
	b.mu.RUnlock()
	if !anyClients {
		return nil
	}

	// Serve the linked-user set from the cache while it is fresh.
	if linked, ok := b.cachedLinks(sourceUserID); ok {
		return append([]int{sourceUserID}, linked...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	links, err := service.GetAcceptedLinkUsers(ctx, b.pool, sourceUserID)
	if err != nil {
		// Don't cache failures — fall back to just the source user.
		slog.Error("failed to load linked users for broadcast", "error", err)
		return []int{sourceUserID}
	}
	linked := make([]int, 0, len(links))
	for _, link := range links {
		linked = append(linked, link.UserID)
	}
	b.storeLinks(sourceUserID, linked)
	return append([]int{sourceUserID}, linked...)
}

// cachedLinks returns the cached accepted-link target IDs for userID when a
// fresh entry exists. The returned slice is owned by the cache and must not be
// mutated by callers (getTargets only ever appends it onto a fresh slice).
func (b *Broker) cachedLinks(userID int) ([]int, bool) {
	b.linkMu.Lock()
	defer b.linkMu.Unlock()
	entry, ok := b.linkCache[userID]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.linked, true
}

func (b *Broker) storeLinks(userID int, linked []int) {
	b.linkMu.Lock()
	defer b.linkMu.Unlock()
	if b.linkCache == nil {
		b.linkCache = make(map[int]linkCacheEntry)
	}
	b.linkCache[userID] = linkCacheEntry{linked: linked, expires: time.Now().Add(linkCacheTTL)}
}

// InvalidateLinks drops any cached accepted-links set for the given users so the
// next broadcast re-resolves it from the database. Callers in the link handlers
// invoke this whenever a user's set of accepted links changes (accept/remove),
// which keeps real-time delivery correct without waiting for the TTL.
func (b *Broker) InvalidateLinks(userIDs ...int) {
	b.linkMu.Lock()
	defer b.linkMu.Unlock()
	for _, id := range userIDs {
		delete(b.linkCache, id)
	}
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
