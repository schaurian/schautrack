package handler

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"schautrack/internal/service"
)

// Behaviour of withIdempotency (invariant #6). Every branch here was
// unexecuted: the ON CONFLICT DO NOTHING claim, the replay, the
// fingerprint-mismatch 409, the in-flight 409, and the release-on-error path at
// v1_idempotency.go:126 — which is the subtlest of them, because getting it
// wrong wedges a client on a mistake it has already fixed.

// entryCount is how many calorie entries the env's user holds. Idempotency is
// about how many rows exist, so that is what these tests assert on.
func (e *v1Env) entryCount() int {
	e.t.Helper()

	var n int
	if err := e.Pool.QueryRow(e.Ctx,
		`SELECT COUNT(*)::int FROM calorie_entries WHERE user_id = $1`, e.UserID).Scan(&n); err != nil {
		e.t.Fatalf("counting entries: %v", err)
	}
	return n
}

func idempotent(key string) map[string]string {
	return map[string]string{idempotencyHeader: key}
}

// TestV1IdempotencyKeyReplaysInsteadOfCreatingTwice is the headline promise: a
// retried POST returns the original response and creates nothing new.
func TestV1IdempotencyKeyReplaysInsteadOfCreatingTwice(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	const body = `{"date":"2026-08-05","calories":450,"name":"Porridge"}`
	c := call{Method: http.MethodPost, Path: "/api/v1/entries", Token: token,
		Body: body, Headers: idempotent("retry-me-once")}

	first := e.do(c)
	if first.Code != http.StatusCreated {
		t.Fatalf("first POST: status = %d, want 201 (body: %s)", first.Code, first.Body.String())
	}
	if first.Header().Get("Idempotency-Replayed") != "" {
		t.Error("the first request was marked as a replay")
	}
	var created v1Entry
	decodeJSON(t, first, &created)

	second := e.do(c)
	if second.Code != http.StatusCreated {
		t.Fatalf("retry: status = %d, want the original 201 (body: %s)", second.Code, second.Body.String())
	}
	if second.Header().Get("Idempotency-Replayed") != "true" {
		t.Error("no Idempotency-Replayed header; a client cannot tell a replay from a second create")
	}
	if got, want := second.Header().Get("Location"), first.Header().Get("Location"); got != want {
		t.Errorf("replayed Location = %q, want %q", got, want)
	}
	if got, want := strings.TrimSpace(second.Body.String()), strings.TrimSpace(first.Body.String()); got != want {
		t.Errorf("replayed body differs from the original:\n got %s\nwant %s", got, want)
	}

	var replayed v1Entry
	decodeJSON(t, second, &replayed)
	if replayed.ID != created.ID {
		t.Errorf("replay returned entry %d, want the original %d", replayed.ID, created.ID)
	}
	if n := e.entryCount(); n != 1 {
		t.Errorf("%d entries exist after a retry with the same key; the meal was logged twice", n)
	}
}

// TestV1IdempotencyWithoutAKeyStillCreatesTwice pins the opt-in contract: the
// feature must not change behaviour for a client that has never heard of it.
func TestV1IdempotencyWithoutAKeyStillCreatesTwice(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	const body = `{"date":"2026-08-05","calories":450}`
	e.post("/api/v1/entries", token, body)
	e.post("/api/v1/entries", token, body)

	if n := e.entryCount(); n != 2 {
		t.Errorf("%d entries, want 2 — without a key two POSTs are two entries", n)
	}
}

// TestV1IdempotencyRejectsAReusedKeyForADifferentRequest covers the fingerprint
// mismatch: replaying would silently discard what the client just asked for.
func TestV1IdempotencyRejectsAReusedKeyForADifferentRequest(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	const key = "recycled"
	first := e.do(call{Method: http.MethodPost, Path: "/api/v1/entries", Token: token,
		Body: `{"date":"2026-08-05","calories":450}`, Headers: idempotent(key)})
	if first.Code != http.StatusCreated {
		t.Fatalf("first POST: status = %d (body: %s)", first.Code, first.Body.String())
	}

	second := e.do(call{Method: http.MethodPost, Path: "/api/v1/entries", Token: token,
		Body: `{"date":"2026-08-05","calories":900}`, Headers: idempotent(key)})

	p := requireProblem(t, second, http.StatusConflict)
	if p.Detail == "" {
		t.Error("the 409 does not say what went wrong")
	}
	if n := e.entryCount(); n != 1 {
		t.Errorf("%d entries; the mismatched retry must not have created one", n)
	}
}

// TestV1IdempotencyKeyIsScopedToTheUser: two accounts using the same key value
// must not collide. A shared key namespace would let one account's retry replay
// another's response.
func TestV1IdempotencyKeyIsScopedToTheUser(t *testing.T) {
	e := newV1Env(t)
	mine := e.token(service.ScopeEntriesWrite)

	otherID, _ := e.seedUser("-other")
	theirs := e.tokenFor(otherID, service.ScopeEntriesWrite)

	const key = "everyone-picks-1"
	const body = `{"date":"2026-08-05","calories":450}`

	a := e.do(call{Method: http.MethodPost, Path: "/api/v1/entries", Token: mine, Body: body, Headers: idempotent(key)})
	b := e.do(call{Method: http.MethodPost, Path: "/api/v1/entries", Token: theirs, Body: body, Headers: idempotent(key)})

	if a.Code != http.StatusCreated || b.Code != http.StatusCreated {
		t.Fatalf("statuses = %d and %d, want 201 twice (bodies: %s / %s)",
			a.Code, b.Code, a.Body.String(), b.Body.String())
	}
	if b.Header().Get("Idempotency-Replayed") == "true" {
		t.Fatal("the second account's request replayed the first account's response")
	}

	var mineEntry, theirsEntry v1Entry
	decodeJSON(t, a, &mineEntry)
	decodeJSON(t, b, &theirsEntry)
	if mineEntry.ID == theirsEntry.ID {
		t.Fatalf("both accounts were handed entry %d", mineEntry.ID)
	}
}

// TestV1IdempotencyReleasesTheClaimAfterAnError is the branch at
// v1_idempotency.go:126, and the reason it exists: a client whose first attempt
// was rejected fixes the body and retries with the SAME key (it is one logical
// operation). If the failed attempt kept the claim, that retry would 409
// forever and the meal could never be logged.
func TestV1IdempotencyReleasesTheClaimAfterAnError(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	const key = "fix-and-retry"

	bad := e.do(call{Method: http.MethodPost, Path: "/api/v1/entries", Token: token,
		Body: fmt.Sprintf(`{"calories":%d}`, MaxEntryCalories+1), Headers: idempotent(key)})
	requireProblem(t, bad, http.StatusUnprocessableEntity)

	// The claim must be gone, not stored as a replayable 422.
	var claims int
	if err := e.Pool.QueryRow(e.Ctx,
		`SELECT COUNT(*)::int FROM api_idempotency WHERE user_id = $1 AND idempotency_key = $2`,
		e.UserID, key).Scan(&claims); err != nil {
		t.Fatalf("counting claims: %v", err)
	}
	if claims != 0 {
		t.Errorf("%d claim rows remain after a 422; the retry below only works because it is released", claims)
	}

	good := e.do(call{Method: http.MethodPost, Path: "/api/v1/entries", Token: token,
		Body: `{"calories":450}`, Headers: idempotent(key)})
	if good.Code != http.StatusCreated {
		t.Fatalf("corrected retry: status = %d, want 201 — the failed attempt pinned the key (body: %s)",
			good.Code, good.Body.String())
	}
	if good.Header().Get("Idempotency-Replayed") == "true" {
		t.Error("the corrected retry replayed the failed attempt instead of executing")
	}
	if n := e.entryCount(); n != 1 {
		t.Errorf("%d entries, want 1", n)
	}
}

// TestV1IdempotencyReportsAnInFlightRequest covers the response_status = 0
// branch. The row is claimed before the handler runs, so a concurrent retry
// observes a claim with no stored response; it must be told to retry rather
// than handed an empty body.
func TestV1IdempotencyReportsAnInFlightRequest(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	const key = "still-running"
	const body = `{"date":"2026-08-05","calories":450}`

	// Stand in for the concurrent original by planting exactly the row it would
	// have written: same fingerprint, response_status still 0.
	req := mustRequest(t, http.MethodPost, "/api/v1/entries", body)
	fingerprint := fingerprintRequest(req, []byte(body))
	if _, err := e.Pool.Exec(e.Ctx, `
		INSERT INTO api_idempotency (user_id, idempotency_key, request_fingerprint)
		VALUES ($1, $2, $3)`, e.UserID, key, fingerprint); err != nil {
		t.Fatalf("planting the in-flight claim: %v", err)
	}

	rec := e.do(call{Method: http.MethodPost, Path: "/api/v1/entries", Token: token,
		Body: body, Headers: idempotent(key)})

	p := requireProblem(t, rec, http.StatusConflict)
	if !strings.Contains(strings.ToLower(p.Detail), "progress") {
		t.Errorf("detail = %q; it should tell the caller the original is still running", p.Detail)
	}
	if n := e.entryCount(); n != 0 {
		t.Errorf("%d entries; a request that saw an in-flight claim must not execute", n)
	}
}

// TestV1IdempotencyKeyLengthIsBounded — an unbounded header would be a cheap
// way to write large rows.
func TestV1IdempotencyKeyLengthIsBounded(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	rec := e.do(call{Method: http.MethodPost, Path: "/api/v1/entries", Token: token,
		Body: `{"calories":450}`, Headers: idempotent(strings.Repeat("k", maxIdempotencyKeyLen+1))})

	requireProblem(t, rec, http.StatusBadRequest)
	if n := e.entryCount(); n != 0 {
		t.Errorf("%d entries; the over-long key must be rejected before the handler runs", n)
	}

	// Exactly at the limit is fine.
	ok := e.do(call{Method: http.MethodPost, Path: "/api/v1/entries", Token: token,
		Body: `{"calories":450}`, Headers: idempotent(strings.Repeat("k", maxIdempotencyKeyLen))})
	if ok.Code != http.StatusCreated {
		t.Fatalf("a %d-character key: status = %d, want 201 (body: %s)",
			maxIdempotencyKeyLen, ok.Code, ok.Body.String())
	}
}

// TestV1IdempotencyAppliesToTrackingASavedFood: the other endpoint CLAUDE.md
// names as wrapped. Tracking twice with one key must produce one entry and one
// use_count increment.
func TestV1IdempotencyAppliesToTrackingASavedFood(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeFoodsWrite, service.ScopeEntriesWrite)

	rec := e.post("/api/v1/saved-foods", token, `{"name":"Banana","calories":105}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("creating the saved food: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var food v1SavedFood
	decodeJSON(t, rec, &food)

	c := call{
		Method: http.MethodPost, Path: fmt.Sprintf("/api/v1/saved-foods/%d/track", food.ID),
		Token: token, Body: `{"date":"2026-08-05","quantity":1}`, Headers: idempotent("track-once"),
	}
	if first := e.do(c); first.Code != http.StatusCreated {
		t.Fatalf("first track: status = %d (body: %s)", first.Code, first.Body.String())
	}
	second := e.do(c)
	if second.Code != http.StatusCreated {
		t.Fatalf("retried track: status = %d, want the original 201 (body: %s)", second.Code, second.Body.String())
	}
	if second.Header().Get("Idempotency-Replayed") != "true" {
		t.Error("the retried track was not marked as a replay")
	}

	if n := e.entryCount(); n != 1 {
		t.Errorf("%d entries after a retried track, want 1", n)
	}
	var useCount int
	if err := e.Pool.QueryRow(e.Ctx,
		`SELECT use_count FROM saved_foods WHERE id = $1`, food.ID).Scan(&useCount); err != nil {
		t.Fatalf("reading use_count: %v", err)
	}
	if useCount != 1 {
		t.Errorf("use_count = %d after a replayed track, want 1", useCount)
	}
}

// TestV1IdempotencyAppliesToCreatingATodo is the replay assertion the TODO on
// this test asked for. #294 wrapped POST /todos and POST /saved-foods in
// withIdempotency, so a retried create now replays the stored response instead
// of writing a second row.
//
// It previously asserted the opposite — two todos, no Idempotency-Replayed —
// to keep the gap visible in the test output while it existed. Left as a
// pinned assertion rather than deleted: the silent double-create is the exact
// failure #294 was filed for, and a retry after a timeout is the normal way to
// hit it.
func TestV1IdempotencyAppliesToCreatingATodo(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeTodosWrite)

	c := call{Method: http.MethodPost, Path: "/api/v1/todos", Token: token,
		Body:    `{"name":"Walk the dog","schedule":{"type":"daily"}}`,
		Headers: idempotent("todo-key")}

	first := e.do(c)
	if first.Code != http.StatusCreated {
		t.Fatalf("first POST /todos: status = %d (body: %s)", first.Code, first.Body.String())
	}
	second := e.do(c)
	if second.Code != http.StatusCreated {
		t.Fatalf("second POST /todos: status = %d (body: %s)", second.Code, second.Body.String())
	}

	var todos int
	if err := e.Pool.QueryRow(e.Ctx,
		`SELECT COUNT(*)::int FROM todos WHERE user_id = $1 AND archived = FALSE`, e.UserID).Scan(&todos); err != nil {
		t.Fatalf("counting todos: %v", err)
	}
	if todos != 1 {
		t.Fatalf("got %d todos after a retried create with the same Idempotency-Key, want 1", todos)
	}
	if second.Header().Get("Idempotency-Replayed") != "true" {
		t.Error("the retried create was not marked as a replay; a client cannot tell it from a second create")
	}
}
