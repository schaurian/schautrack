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
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/session"
	"schautrack/internal/sse"
)

// The tests in this file pin that every way a link disappears — one side
// removing it, or an account being deleted by its owner, an admin or the
// unverified-signup reaper — drops the SSE link caches that still name it, so
// activity events stop crossing it right away instead of for the cache TTL.
// Each warms a cache through a real broadcast first, so a missing invalidation
// shows up as an event that should not have arrived.

type lifecycleEnv struct {
	t    *testing.T
	ctx  context.Context
	pool *pgxpool.Pool
	url  string
}

func newLifecycleEnv(t *testing.T) *lifecycleEnv {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return &lifecycleEnv{t: t, ctx: ctx, pool: pool, url: url}
}

// linkedPair seeds two accounts with an accepted link on which each shares
// nutrition with the other; the owner's verification state and age are set so
// the reaper case can qualify.
func (e *lifecycleEnv) linkedPair(prefix string, ownerVerified bool, ownerAge time.Duration) (ownerID, friendID, linkID int) {
	e.t.Helper()
	owner, friend := prefix+"-owner@handler.test", prefix+"-friend@handler.test"
	del := func() { e.pool.Exec(context.Background(), `DELETE FROM users WHERE email IN ($1, $2)`, owner, friend) }
	del()
	e.t.Cleanup(del)
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO users (email, password_hash, email_verified, created_at)
		VALUES ($1, 'x', $2, NOW() - $3::interval) RETURNING id`,
		owner, ownerVerified, ownerAge.String()).Scan(&ownerID); err != nil {
		e.t.Fatalf("seed owner: %v", err)
	}
	if err := e.pool.QueryRow(e.ctx,
		`INSERT INTO users (email, password_hash, email_verified) VALUES ($1, 'x', true) RETURNING id`,
		friend).Scan(&friendID); err != nil {
		e.t.Fatalf("seed friend: %v", err)
	}
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO account_links (requester_id, target_id, status, requester_shares, target_shares)
		VALUES ($1, $2, 'accepted', '{"nutrition": true}'::jsonb, '{"nutrition": true}'::jsonb) RETURNING id`,
		ownerID, friendID).Scan(&linkID); err != nil {
		e.t.Fatalf("seed link: %v", err)
	}
	return ownerID, friendID, linkID
}

// replica starts a broker with its own listener, as one app instance.
func (e *lifecycleEnv) replica() *sse.Broker {
	b := sse.NewBroker(e.pool)
	ctx, stop := context.WithCancel(e.ctx)
	e.t.Cleanup(stop)
	go b.Listen(ctx, e.url)
	return b
}

// subscribe returns userID's stream on b once b's listener demonstrably
// delivers, with any late readiness probes flushed.
func (e *lifecycleEnv) subscribe(b *sse.Broker, userID int) chan []byte {
	e.t.Helper()
	ch := b.Subscribe(userID)
	e.t.Cleanup(func() { b.Unsubscribe(userID, ch) })
	ready := false
	for deadline := time.Now().Add(10 * time.Second); !ready && time.Now().Before(deadline); {
		b.SendEvent(userID, "ready", map[string]any{})
		select {
		case <-ch:
			ready = true
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !ready {
		e.t.Fatal("SSE listener never came up")
	}
	b.SendEvent(userID, "flushed", map[string]any{})
	e.until(ch, "flushed")
	return ch
}

// until returns every frame received on ch before the marker event.
func (e *lifecycleEnv) until(ch chan []byte, marker string) []string {
	e.t.Helper()
	var got []string
	for {
		select {
		case msg := <-ch:
			if strings.Contains(string(msg), "event: "+marker) {
				return got
			}
			got = append(got, string(msg))
		case <-time.After(10 * time.Second):
			e.t.Fatalf("marker %s never arrived", marker)
			return nil
		}
	}
}

// expectWarm broadcasts from source on b and requires the listener to see it,
// which also fills b's link cache for source.
func (e *lifecycleEnv) expectWarm(b *sse.Broker, source, listener int, ch chan []byte) {
	e.t.Helper()
	b.BroadcastEntryChange(source)
	b.SendEvent(listener, "warm", map[string]any{})
	if got := e.until(ch, "warm"); len(got) != 1 {
		e.t.Fatalf("while linked, %d got %d events, want 1: %q", listener, len(got), got)
	}
}

// expectSilent broadcasts from source on b and requires listener to get nothing.
func (e *lifecycleEnv) expectSilent(b *sse.Broker, source, listener int, ch chan []byte, why string) {
	e.t.Helper()
	b.BroadcastEntryChange(source)
	b.SendEvent(listener, "marker", map[string]any{})
	if got := e.until(ch, "marker"); len(got) != 0 {
		e.t.Fatalf("%s, yet %d still received %q", why, listener, got)
	}
}

func postAs(user *model.User, path, body string, params map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	return req.WithContext(middleware.WithTestUser(ctx, user))
}

// TestLinkRemoveClearsTheOtherSidesCacheOnOtherReplicas: the FRIEND removes
// the link on replica B, so it is the OWNER's cache on replica A — the second
// id InvalidateLinks is given — that must be dropped.
func TestLinkRemoveClearsTheOtherSidesCacheOnOtherReplicas(t *testing.T) {
	e := newLifecycleEnv(t)
	ownerID, friendID, linkID := e.linkedPair("remove-replica", true, 0)
	replicaA, replicaB := e.replica(), e.replica()
	friendOnA := e.subscribe(replicaA, friendID)
	e.subscribe(replicaB, ownerID) // proves B's listener is up

	e.expectWarm(replicaA, ownerID, friendID, friendOnA)

	h := &LinksHandler{Pool: e.pool, Broker: replicaB}
	rec := httptest.NewRecorder()
	h.LinkRemove(rec, postAs(&model.User{ID: friendID}, "/settings/link/remove",
		`{"link_id": `+strconv.Itoa(linkID)+`}`, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("LinkRemove = %d: %s", rec.Code, rec.Body.String())
	}
	// Published after the invalidation: once A delivers it, A has applied it.
	replicaB.SendEvent(friendID, "synced", map[string]any{})
	e.until(friendOnA, "synced")

	e.expectSilent(replicaA, ownerID, friendID, friendOnA, "the friend removed the link on another replica")
}

// TestAccountDeletionClearsPartnersCaches covers the three delete paths. The
// deleted account's stream stays subscribed, standing in for a tab still open
// on another device: a partner's stale cache would keep sending it events.
func TestAccountDeletionClearsPartnersCaches(t *testing.T) {
	cases := []struct {
		name          string
		ownerVerified bool
		ownerAge      time.Duration
		del           func(e *lifecycleEnv, b *sse.Broker, ownerID int)
	}{
		{"own account deletion", true, 0, func(e *lifecycleEnv, b *sse.Broker, ownerID int) {
			h := &AuthHandler{Pool: e.pool, Cfg: &config.Config{}, Broker: b, SessionStore: session.NewStore(e.pool)}
			rec := httptest.NewRecorder()
			req := postAs(&model.User{ID: ownerID}, "/delete", `{}`, nil)
			req = req.WithContext(session.WithTestSession(req.Context(), &session.Session{ID: "lifecycle-test", Data: map[string]any{}}))
			h.DeleteAccount(rec, req)
			if rec.Code != http.StatusOK {
				e.t.Fatalf("DeleteAccount = %d: %s", rec.Code, rec.Body.String())
			}
		}},
		{"admin delete", true, 0, func(e *lifecycleEnv, b *sse.Broker, ownerID int) {
			h := &AdminHandler{Pool: e.pool, Broker: b}
			rec := httptest.NewRecorder()
			h.DeleteUser(rec, postAs(&model.User{ID: -1}, "/admin/users/x/delete", `{}`,
				map[string]string{"id": strconv.Itoa(ownerID)}))
			if rec.Code != http.StatusOK {
				e.t.Fatalf("DeleteUser = %d: %s", rec.Code, rec.Body.String())
			}
		}},
		{"unverified reaper", false, 2 * time.Hour, func(e *lifecycleEnv, b *sse.Broker, ownerID int) {
			CleanExpiredTokens(e.pool, b)
			var gone bool
			if err := e.pool.QueryRow(e.ctx, `SELECT NOT EXISTS (SELECT 1 FROM users WHERE id = $1)`, ownerID).Scan(&gone); err != nil || !gone {
				e.t.Fatalf("the reaper did not delete the unverified account (err %v)", err)
			}
		}},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newLifecycleEnv(t)
			ownerID, friendID, _ := e.linkedPair("delete-"+strconv.Itoa(i), c.ownerVerified, c.ownerAge)
			b := e.replica()
			ownerStream := e.subscribe(b, ownerID)

			e.expectWarm(b, friendID, ownerID, ownerStream)
			c.del(e, b, ownerID)
			e.expectSilent(b, friendID, ownerID, ownerStream, "the account was deleted")
		})
	}
}
