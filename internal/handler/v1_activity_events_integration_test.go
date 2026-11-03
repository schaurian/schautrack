package handler

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"schautrack/internal/service"
	"schautrack/internal/sse"
)

// TestV1WritesAnnounceTheirOwnCategory pins that a v1 weight or note write
// emits the event of its own category — so the owner's open tab refreshes the
// right thing, and a linked friend shared only nutrition hears nothing.
//
// Both used to go out as entry-change (the nutrition event): the friend learned
// "they just weighed in / wrote a note" without being shared either, and the
// owner's notes view never refreshed on an API-driven note write.
func TestV1WritesAnnounceTheirOwnCategory(t *testing.T) {
	e := newV1Env(t)
	friendID, _ := e.seedUser("-friend")
	if _, err := e.Pool.Exec(e.Ctx, `
		INSERT INTO account_links (requester_id, target_id, status, requester_shares, target_shares)
		VALUES ($1, $2, 'accepted', '{"nutrition": true}'::jsonb, '{}'::jsonb)`,
		e.UserID, friendID); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	broker := sse.NewBroker(e.Pool)
	listenCtx, stop := context.WithCancel(e.Ctx)
	defer stop()
	go broker.Listen(listenCtx, os.Getenv("TEST_DATABASE_URL"))
	owner := broker.Subscribe(e.UserID)
	defer broker.Unsubscribe(e.UserID, owner)
	friend := broker.Subscribe(friendID)
	defer broker.Unsubscribe(friendID, friend)

	h := &V1Handler{Pool: e.Pool, Broker: broker, BuildVersion: "v1-integration-test"}
	r := chi.NewRouter()
	r.Mount("/api/v1", h.MountAPIV1(e.Pool))
	e.Router = r

	// Wait until the listener delivers before asserting anything.
	ready := false
	for deadline := time.Now().Add(10 * time.Second); !ready && time.Now().Before(deadline); {
		broker.SendEvent(e.UserID, "ready", map[string]any{})
		select {
		case <-owner:
			ready = true
		case <-time.After(200 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("SSE listener never came up")
	}
	// Flush late copies of the readiness probe up to a marker.
	flush := func(ch chan []byte, marker string) []string {
		var got []string
		for {
			select {
			case msg := <-ch:
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
	broker.SendEvent(e.UserID, "flushed", map[string]any{})
	flush(owner, "flushed")

	token := e.token(service.ScopeWeightWrite, service.ScopeNotesWrite)
	cases := []struct {
		path, body, wantEvent string
	}{
		{"/api/v1/weight/2026-11-03", `{"weight": 80.5}`, "entry-change"},
		{"/api/v1/notes/2026-11-03", `{"content": "private"}`, "note-change"},
	}
	for _, c := range cases {
		rec := e.do(call{Method: http.MethodPut, Path: c.path, Token: token, Body: c.body})
		if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
			t.Fatalf("PUT %s = %d: %s", c.path, rec.Code, rec.Body.String())
		}
		broker.SendEvent(e.UserID, "marker", map[string]any{})
		broker.SendEvent(friendID, "marker", map[string]any{})

		ownerGot := flush(owner, "marker")
		if len(ownerGot) != 1 || !strings.Contains(ownerGot[0], "event: "+c.wantEvent) {
			t.Errorf("PUT %s: owner got %q, want exactly one %s", c.path, ownerGot, c.wantEvent)
		}
		if friendGot := flush(friend, "marker"); len(friendGot) != 0 {
			t.Errorf("PUT %s: friend shared only nutrition received %q", c.path, friendGot)
		}
	}
}
