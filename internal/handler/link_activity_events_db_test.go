package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/sse"
)

// TestRevokedShareStopsActivityEventsImmediately pins that a friend stops
// receiving a category's live activity events the moment the owner unshares it.
//
// The broker caches each user's links together with their shares, so without
// SetShares dropping that cache the friend would keep being told "they just
// logged a meal" for the rest of the cache TTL after losing nutrition.
//
// Skipped unless TEST_DATABASE_URL is set (handler TestMain starts one when
// Docker is available).
func TestRevokedShareStopsActivityEventsImmediately(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	const ownerEmail, friendEmail = "activity-owner@handler.test", "activity-friend@handler.test"
	cleanup := func() {
		pool.Exec(ctx, `DELETE FROM users WHERE email IN ($1, $2)`, ownerEmail, friendEmail)
	}
	cleanup()
	t.Cleanup(cleanup)

	var ownerID, friendID, linkID int
	for _, u := range []struct {
		email string
		id    *int
	}{{ownerEmail, &ownerID}, {friendEmail, &friendID}} {
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (email, password_hash, email_verified) VALUES ($1, 'x', true) RETURNING id`,
			u.email).Scan(u.id); err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO account_links (requester_id, target_id, status, requester_shares, target_shares)
		VALUES ($1, $2, 'accepted', '{"nutrition": true}'::jsonb, '{}'::jsonb) RETURNING id`,
		ownerID, friendID).Scan(&linkID); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	// A broker with a pool publishes through pg_notify and delivers what its
	// listener hears, exactly as in production.
	broker := sse.NewBroker(pool)
	listenCtx, stopListen := context.WithCancel(ctx)
	defer stopListen()
	go broker.Listen(listenCtx, url)
	friend := broker.Subscribe(friendID)
	defer broker.Unsubscribe(friendID, friend)

	// While nutrition is shared the friend gets the event — this also warms
	// the broker's link cache with the shared state. Retried until the
	// listener is up.
	got := false
	for deadline := time.Now().Add(10 * time.Second); !got && time.Now().Before(deadline); {
		broker.BroadcastEntryChange(ownerID)
		select {
		case msg := <-friend:
			got = strings.Contains(string(msg), "event: entry-change")
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !got {
		t.Fatal("friend shared nutrition did not receive entry-change")
	}
	// Late copies of the retried warm-up broadcast must not be mistaken for a
	// leak below: flush everything up to a first sentinel.
	broker.SendEvent(friendID, "warm", map[string]any{})
	for flushed := false; !flushed; {
		select {
		case msg := <-friend:
			flushed = strings.Contains(string(msg), "event: warm")
		case <-time.After(10 * time.Second):
			t.Fatal("warm-up sentinel never arrived")
		}
	}

	h := &LinksHandler{Pool: pool, Broker: broker}
	req := httptest.NewRequest(http.MethodPost, "/links/"+strconv.Itoa(linkID)+"/shares",
		strings.NewReader(`{"nutrition": false}`))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", strconv.Itoa(linkID))
	c := context.WithValue(ctx, chi.RouteCtxKey, rctx)
	req = req.WithContext(middleware.WithTestUser(c, &model.User{ID: ownerID, Email: ownerEmail}))
	rec := httptest.NewRecorder()
	h.SetShares(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("SetShares = %d: %s", rec.Code, rec.Body.String())
	}

	// Then an entry change, then a sentinel. Events reach the friend in publish
	// order, so everything before the sentinel is what the entry change caused.
	broker.BroadcastEntryChange(ownerID)
	broker.SendEvent(friendID, "sentinel", map[string]any{})
	for {
		select {
		case msg := <-friend:
			if strings.Contains(string(msg), "event: sentinel") {
				return
			}
			if strings.Contains(string(msg), "event: entry-change") {
				t.Fatalf("friend no longer shared nutrition still received %s", msg)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("sentinel never arrived")
		}
	}
}

// TestSessionWeightWriteReachesOnlyWeightSharers pins that the app's own weight
// upsert announces itself as a weight change: a friend shared only nutrition
// must not learn that the owner just weighed in.
func TestSessionWeightWriteReachesOnlyWeightSharers(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	const ownerEmail, friendEmail = "weight-owner@handler.test", "weight-friend@handler.test"
	cleanup := func() {
		pool.Exec(ctx, `DELETE FROM users WHERE email IN ($1, $2)`, ownerEmail, friendEmail)
	}
	cleanup()
	t.Cleanup(cleanup)
	var ownerID, friendID int
	if err := pool.QueryRow(ctx, `INSERT INTO users (email, password_hash, email_verified, timezone)
		VALUES ($1, 'x', true, 'UTC') RETURNING id`, ownerEmail).Scan(&ownerID); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO users (email, password_hash, email_verified)
		VALUES ($1, 'x', true) RETURNING id`, friendEmail).Scan(&friendID); err != nil {
		t.Fatalf("seed friend: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO account_links (requester_id, target_id, status, requester_shares, target_shares)
		VALUES ($1, $2, 'accepted', '{"nutrition": true}'::jsonb, '{}'::jsonb)`, ownerID, friendID); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	broker := sse.NewBroker(pool)
	listenCtx, stopListen := context.WithCancel(ctx)
	defer stopListen()
	go broker.Listen(listenCtx, url)
	friend := broker.Subscribe(friendID)
	defer broker.Unsubscribe(friendID, friend)

	// Wait for the listener, then flush late copies of the probe.
	ready := false
	for deadline := time.Now().Add(10 * time.Second); !ready && time.Now().Before(deadline); {
		broker.SendEvent(friendID, "ready", map[string]any{})
		select {
		case <-friend:
			ready = true
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("SSE listener never came up")
	}
	until := func(marker string) []string {
		var got []string
		for {
			select {
			case msg := <-friend:
				if strings.Contains(string(msg), "event: "+marker) {
					return got
				}
				got = append(got, string(msg))
			case <-time.After(10 * time.Second):
				t.Fatalf("marker %s never arrived", marker)
				return nil
			}
		}
	}
	broker.SendEvent(friendID, "flushed", map[string]any{})
	until("flushed")

	h := &WeightHandler{Pool: pool, Broker: broker}
	req := httptest.NewRequest(http.MethodPost, "/weight/upsert", strings.NewReader(`{"weight": "81"}`))
	req.Header.Set("Content-Type", "application/json")
	tz := "UTC"
	req = req.WithContext(middleware.WithTestUser(ctx, &model.User{ID: ownerID, Email: ownerEmail, Timezone: &tz}))
	rec := httptest.NewRecorder()
	h.WeightUpsert(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("WeightUpsert = %d: %s", rec.Code, rec.Body.String())
	}

	broker.SendEvent(friendID, "marker", map[string]any{})
	if got := until("marker"); len(got) != 0 {
		t.Fatalf("friend shared only nutrition received %q after a weight write", got)
	}
}
