package handler

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"schautrack/internal/service"
)

// Behaviour of resolveTarget — the `?user=` parameter that lets a token read a
// linked account's shared data. This is the highest-consequence branch on the
// whole surface: every failure mode here is either a data leak or a lockout,
// and none of it was executed by a test.

// link creates an accepted account link and sets what each side shares.
// shares maps a service.Share* category to whether that side shares it.
func (e *v1Env) link(requesterID, targetID int, requesterShares, targetShares map[string]bool) {
	e.t.Helper()

	if _, err := e.Pool.Exec(e.Ctx, `
		INSERT INTO account_links (requester_id, target_id, status, requester_shares, target_shares)
		VALUES ($1, $2, 'accepted', $3, $4)`,
		requesterID, targetID, shareJSON(requesterShares), shareJSON(targetShares)); err != nil {
		e.t.Fatalf("linking %d and %d: %v", requesterID, targetID, err)
	}
}

func shareJSON(m map[string]bool) map[string]bool {
	out := map[string]bool{}
	for _, c := range service.ShareCategories {
		out[c] = m[c]
	}
	return out
}

// all / none are the two share sets the tests use.
func allShares() map[string]bool {
	out := map[string]bool{}
	for _, c := range service.ShareCategories {
		out[c] = true
	}
	return out
}

func noShares() map[string]bool { return map[string]bool{} }

// linkedReadEndpoints are the routes that honour ?user=. Kept as a list rather
// than derived, because the set is a deliberate product decision — see #293,
// which is about the routes that are NOT on it.
var linkedReadEndpoints = []struct {
	name, path, scope string
}{
	{"entries", "/api/v1/entries", service.ScopeEntriesRead},
	{"weight", "/api/v1/weight", service.ScopeWeightRead},
	{"todos for a day", "/api/v1/todos/day/2026-08-05", service.ScopeTodosRead},
	{"notes", "/api/v1/notes/2026-08-05", service.ScopeNotesRead},
}

// TestV1LinkedReadsRejectAnUnlinkedAccount is the leak test: pointing ?user= at
// an account you are not linked to must be refused, and refused with 403 rather
// than 404 — a 404 that turned into a 403 once the id existed would be an
// oracle for enumerating accounts.
func TestV1LinkedReadsRejectAnUnlinkedAccount(t *testing.T) {
	e := newV1Env(t)
	strangerID, _ := e.seedUser("-stranger")

	for _, ep := range linkedReadEndpoints {
		t.Run(ep.name, func(t *testing.T) {
			token := e.token(ep.scope, service.ScopeLinksRead)
			rec := e.get(fmt.Sprintf("%s?user=%d", ep.path, strangerID), token)

			requireProblem(t, rec, http.StatusForbidden)
			if body := rec.Body.String(); containsAny(body, `"data"`, `"content"`) {
				t.Errorf("the refusal carried payload fields: %s", body)
			}
		})
	}
}

// TestV1LinkedReadsRejectANonexistentAccount: an id nobody owns must look
// exactly like an id you are simply not linked to.
func TestV1LinkedReadsRejectANonexistentAccount(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesRead, service.ScopeLinksRead)

	rec := e.get("/api/v1/entries?user=2147483000", token)
	requireProblem(t, rec, http.StatusForbidden)
}

// TestV1LinkedReadsNeedTheLinksScope: being linked is not enough — the token
// must also carry links:read, and the 403 must name it so the client knows what
// to re-mint.
func TestV1LinkedReadsNeedTheLinksScope(t *testing.T) {
	e := newV1Env(t)

	friendID, _ := e.seedUser("-friend")
	e.link(friendID, e.UserID, allShares(), allShares())

	token := e.token(service.ScopeEntriesRead) // no links:read
	rec := e.get(fmt.Sprintf("/api/v1/entries?user=%d", friendID), token)

	p := requireProblem(t, rec, http.StatusForbidden)
	if p.RequiredScope != service.ScopeLinksRead {
		t.Errorf("required_scope = %q, want %q", p.RequiredScope, service.ScopeLinksRead)
	}
}

// TestV1LinkedReadsRespectTheSharedCategory: a link that shares weight does not
// share nutrition. The check is per-category, not per-link.
func TestV1LinkedReadsRespectTheSharedCategory(t *testing.T) {
	e := newV1Env(t)

	friendID, _ := e.seedUser("-friend")
	// The friend is the requester and shares only weight with us.
	e.link(friendID, e.UserID, map[string]bool{service.ShareWeight: true}, allShares())

	weightToken := e.token(service.ScopeWeightRead, service.ScopeLinksRead)
	if rec := e.get(fmt.Sprintf("/api/v1/weight?user=%d", friendID), weightToken); rec.Code != http.StatusOK {
		t.Fatalf("weight is shared but the read was refused: status = %d (body: %s)", rec.Code, rec.Body.String())
	}

	entriesToken := e.token(service.ScopeEntriesRead, service.ScopeLinksRead)
	rec := e.get(fmt.Sprintf("/api/v1/entries?user=%d", friendID), entriesToken)
	p := requireProblem(t, rec, http.StatusForbidden)
	if p.Detail == "" {
		t.Error("the 403 does not say which category is missing")
	}
}

// TestV1LinkedReadsReturnTheirDataWhenShared is the positive half — without it
// the tests above would pass on an endpoint that refuses everything.
func TestV1LinkedReadsReturnTheirDataWhenShared(t *testing.T) {
	e := newV1Env(t)

	friendID, _ := e.seedUser("-friend")
	e.link(friendID, e.UserID, allShares(), noShares())

	friendToken := e.tokenFor(friendID, service.ScopeEntriesWrite)
	rec := e.post("/api/v1/entries", friendToken, `{"date":"2026-08-05","calories":777,"name":"Their lunch"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seeding the friend's entry: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var theirs v1Entry
	decodeJSON(t, rec, &theirs)

	token := e.token(service.ScopeEntriesRead, service.ScopeLinksRead)
	list := e.get(fmt.Sprintf("/api/v1/entries?user=%d", friendID), token)
	if list.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", list.Code, list.Body.String())
	}
	requireSchema(t, list, "EntryList")

	var page v1List[v1Entry]
	decodeJSON(t, list, &page)
	found := false
	for _, en := range page.Data {
		if en.ID == theirs.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("the shared entry %d is missing from %s", theirs.ID, list.Body.String())
	}

	// Without ?user= the same token must see nothing of theirs.
	own := e.get("/api/v1/entries", token)
	var ownPage v1List[v1Entry]
	decodeJSON(t, own, &ownPage)
	if len(ownPage.Data) != 0 {
		t.Errorf("our own entries list is not empty: %s", own.Body.String())
	}
}

// TestV1LinkedWritesAreNotPossible: ?user= is a read-only facility. A write
// endpoint that honoured it would let a token mutate someone else's account.
func TestV1LinkedWritesAreNotPossible(t *testing.T) {
	e := newV1Env(t)

	friendID, _ := e.seedUser("-friend")
	e.link(friendID, e.UserID, allShares(), allShares())

	token := e.token(service.ScopeEntriesWrite, service.ScopeLinksRead)
	rec := e.post(fmt.Sprintf("/api/v1/entries?user=%d", friendID), token,
		`{"date":"2026-08-05","calories":450,"name":"Not yours"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}

	// The entry must belong to the caller, not to the account named in ?user=.
	var owner int
	if err := e.Pool.QueryRow(e.Ctx,
		`SELECT user_id FROM calorie_entries WHERE entry_name = 'Not yours'`).Scan(&owner); err != nil {
		t.Fatalf("finding the created entry: %v", err)
	}
	if owner != e.UserID {
		t.Fatalf("the entry was written to account %d; ?user= must never redirect a write (caller is %d)",
			owner, e.UserID)
	}
}

// TestV1LinkedReadOfYourOwnIdIsAllowed: ?user=<self> is a no-op, and must not
// require links:read.
func TestV1LinkedReadOfYourOwnIdIsAllowed(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesRead)

	rec := e.get(fmt.Sprintf("/api/v1/entries?user=%d", e.UserID), token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestV1LinksListsWhatEachSideShares covers GET /links, including the direction
// of shares_with_me vs shares_to_them — getting them backwards would tell a
// client it can read data it cannot.
func TestV1LinksListsWhatEachSideShares(t *testing.T) {
	e := newV1Env(t)

	friendID, friendEmail := e.seedUser("-friend")
	// The friend shares everything with us; we share nothing back.
	e.link(friendID, e.UserID, allShares(), noShares())

	rec := e.get("/api/v1/links", e.token(service.ScopeLinksRead))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	requireSchema(t, rec, "LinkList")

	var page v1List[v1Link]
	decodeJSON(t, rec, &page)
	if len(page.Data) != 1 {
		t.Fatalf("got %d links, want 1: %s", len(page.Data), rec.Body.String())
	}
	l := page.Data[0]
	if l.UserID != friendID {
		t.Errorf("user_id = %d, want %d", l.UserID, friendID)
	}
	if l.Email != friendEmail {
		t.Errorf("email = %q, want %q", l.Email, friendEmail)
	}
	for _, c := range service.ShareCategories {
		if !l.SharesWithMe[c] {
			t.Errorf("shares_with_me[%s] = false, but the friend shares it", c)
		}
		if l.SharesToThem[c] {
			t.Errorf("shares_to_them[%s] = true, but we share nothing", c)
		}
	}

	// The user_id GET /links hands out must be usable as ?user= — that is the
	// documented purpose of the field.
	follow := e.get(fmt.Sprintf("/api/v1/entries?user=%d", l.UserID),
		e.token(service.ScopeEntriesRead, service.ScopeLinksRead))
	if follow.Code != http.StatusOK {
		t.Errorf("?user=%d from GET /links was refused: status = %d (body: %s)",
			l.UserID, follow.Code, follow.Body.String())
	}
}

// TestV1LinkedEntryIdsAreNotFetchableIndividually documents the bug #293 owns:
// GET /entries?user= hands out ids that GET /entries/{id} cannot resolve,
// because that endpoint never calls resolveTarget.
//
// TODO(#293): when GET /entries/{id} honours ?user=, this becomes a 200 and the
// assertion flips. It is here as the current behaviour rather than as a
// weakened version of the right one, so the fix has a test waiting for it.
func TestV1LinkedEntryIdsAreNotFetchableIndividually(t *testing.T) {
	e := newV1Env(t)

	friendID, _ := e.seedUser("-friend")
	e.link(friendID, e.UserID, allShares(), noShares())

	friendToken := e.tokenFor(friendID, service.ScopeEntriesWrite)
	rec := e.post("/api/v1/entries", friendToken, `{"date":"2026-08-05","calories":777}`)
	var theirs v1Entry
	decodeJSON(t, rec, &theirs)

	token := e.token(service.ScopeEntriesRead, service.ScopeLinksRead)

	list := e.get(fmt.Sprintf("/api/v1/entries?user=%d", friendID), token)
	var page v1List[v1Entry]
	decodeJSON(t, list, &page)
	if len(page.Data) == 0 {
		t.Fatalf("the collection returned nothing to follow: %s", list.Body.String())
	}

	one := e.get(fmt.Sprintf("/api/v1/entries/%d?user=%d", theirs.ID, friendID), token)
	if one.Code != http.StatusNotFound {
		t.Fatalf("status = %d; if GET /entries/{id} now honours ?user= (#293), update this test "+
			"to assert 200 and the entry's contents (body: %s)", one.Code, one.Body.String())
	}
	requireProblemShape(t, one)
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
