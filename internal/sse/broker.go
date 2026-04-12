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

// Broker manages SSE connections per user.
type Broker struct {
	mu      sync.RWMutex
	clients map[int]map[chan []byte]struct{}
	pool    *pgxpool.Pool
}

func NewBroker(pool *pgxpool.Pool) *Broker {
	b := &Broker{
		clients: make(map[int]map[chan []byte]struct{}),
		pool:    pool,
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

func (b *Broker) getTargets(sourceUserID int) []int {
	targets := []int{sourceUserID}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	links, err := service.GetAcceptedLinkUsers(ctx, b.pool, sourceUserID)
	if err != nil {
		slog.Error("failed to load linked users for broadcast", "error", err)
		return targets
	}
	for _, link := range links {
		targets = append(targets, link.UserID)
	}
	return targets
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
