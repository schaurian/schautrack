package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/openapi"
	"schautrack/internal/service"
)

// The ?user= parameter is the only cross-account read path in /api/v1, which
// makes resolveTarget the authorization boundary for every one of them. These
// tests pin both halves of that: which endpoints offer the parameter (it must
// be the same set the spec advertises, or a client following a documented
// list-then-fetch pattern hits a 404 dead end), and that offering it never
// widens what an unlinked or unshared caller can read.

// linkedReadEndpoint is one v1 read endpoint that routes through resolveTarget.
type linkedReadEndpoint struct {
	// name doubles as the spec key, so the DB-free tests and the spec-parity
	// test cannot disagree about which endpoint is which.
	name   string
	params map[string]string
	call   func(h *V1Handler, w http.ResponseWriter, r *http.Request)
}

// linkedReadHandlers is every read endpoint that honours ?user=, paired with
// the handler to invoke. Named for what it holds rather than what it covers,
// because v1_links_integration_test.go already declares a linkedReadEndpoints —
// a shorter, DB-backed list for the same feature. Adding an endpoint here
// without listing it here leaves it untested; listing one that does not honour
// the parameter fails TestV1SpecDocumentsUserParamExactlyWhereItWorks.
var linkedReadHandlers = []linkedReadEndpoint{
	{"GET /entries", nil,
		func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.ListEntries(w, r) }},
	{"GET /entries/{id}", map[string]string{"id": "1"},
		func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.GetEntryV1(w, r) }},
	{"GET /weight", nil,
		func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.ListWeight(w, r) }},
	{"GET /weight/{date}", map[string]string{"date": "2026-08-05"},
		func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.GetWeightV1(w, r) }},
	{"GET /todos", nil,
		func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.ListTodosV1(w, r) }},
	{"GET /todos/day/{date}", map[string]string{"date": "2026-08-05"},
		func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.TodosForDayV1(w, r) }},
	{"GET /notes/{date}", map[string]string{"date": "2026-08-05"},
		func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.GetNoteV1(w, r) }},
}

// v1ReadRequest builds a request as the router would have left it: chi path
// params populated, the authenticated user and its token in the context.
func v1ReadRequest(target string, params map[string]string, user *model.User, token *model.APIToken) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = middleware.WithTestUser(ctx, user)
	if token != nil {
		ctx = middleware.WithTestAPIToken(ctx, token)
	}
	return r.WithContext(ctx)
}

// callNilPool runs a handler built with no database and turns the resulting
// panic into a readable failure.
//
// The panic is the assertion: a handler that ignores ?user= and queries under
// the caller's own id dereferences the nil pool. Left unrecovered it would tear
// down the whole package's test binary and report as a stack trace, so it is
// converted into a failure that names what actually went wrong.
func callNilPool(t *testing.T, ep linkedReadEndpoint, rec *httptest.ResponseRecorder, r *http.Request) {
	t.Helper()
	defer func() {
		if v := recover(); v != nil {
			t.Fatalf("%s reached the database before authorizing ?user= (panicked on the nil pool: %v) — "+
				"resolveTarget has to run first, or the parameter is honoured without a permission check",
				ep.name, v)
		}
	}()
	ep.call(&V1Handler{}, rec, r)
}

// readProblem decodes an RFC 9457 body.
func readProblem(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var p map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("response is not JSON: %v (body %q)", err, rec.Body.String())
	}
	return p
}

// TestLinkedReadWithoutLinksScopeIsRejected is the denial path that costs
// nothing to get wrong and everything to miss: a token that can read entries
// but was never granted links:read must not be able to name another account.
//
// The handler is built with a nil pool on purpose. resolveTarget has to reject
// before it queries anything, so a regression that checked the link table first
// and the scope second would panic here rather than pass quietly.
func TestLinkedReadWithoutLinksScopeIsRejected(t *testing.T) {
	caller := &model.User{ID: 1, Email: "caller@example.com", WeightUnit: "kg"}

	// Every read scope, but deliberately not links:read.
	token := &model.APIToken{ID: 1, UserID: 1, Scopes: []string{
		service.ScopeEntriesRead, service.ScopeWeightRead,
		service.ScopeTodosRead, service.ScopeNotesRead,
	}}

	for _, ep := range linkedReadHandlers {
		t.Run(ep.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			callNilPool(t, ep, rec, v1ReadRequest("/?user=42", ep.params, caller, token))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (body %q)", rec.Code, rec.Body.String())
			}
			p := readProblem(t, rec)
			if p["required_scope"] != service.ScopeLinksRead {
				t.Errorf("required_scope = %v, want %q", p["required_scope"], service.ScopeLinksRead)
			}
		})
	}
}

// A request carrying no token at all must fail closed the same way. This is the
// routing-mistake case: if a linked read were ever mounted outside
// RequireAPIToken, treating a missing token as "no restriction" would serve
// another account's data to an anonymous caller.
func TestLinkedReadWithoutTokenIsRejected(t *testing.T) {
	caller := &model.User{ID: 1, Email: "caller@example.com"}
	for _, ep := range linkedReadHandlers {
		t.Run(ep.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			callNilPool(t, ep, rec, v1ReadRequest("/?user=42", ep.params, caller, nil))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (body %q)", rec.Code, rec.Body.String())
			}
		})
	}
}

// A malformed ?user= is a 400, not a silent fallback to the caller's own data —
// serving your own entries in response to a typo'd account id would look like
// success while answering a different question.
func TestLinkedReadRejectsMalformedUserParam(t *testing.T) {
	caller := &model.User{ID: 1, Email: "caller@example.com"}
	token := &model.APIToken{ID: 1, UserID: 1, Scopes: service.AllScopes()}

	for _, raw := range []string{"abc", "0", "-1", "1.5", "42x"} {
		for _, ep := range linkedReadHandlers {
			t.Run(raw+" "+ep.name, func(t *testing.T) {
				rec := httptest.NewRecorder()
				callNilPool(t, ep, rec, v1ReadRequest("/?user="+raw, ep.params, caller, token))

				if rec.Code != http.StatusBadRequest {
					t.Fatalf("?user=%s: status = %d, want 400 (body %q)", raw, rec.Code, rec.Body.String())
				}
			})
		}
	}
}

// --- Spec parity ----------------------------------------------------------

// specGETsWithUserParam returns every GET operation in the document that
// advertises the `user` query parameter.
func specGETsWithUserParam(t *testing.T) []string {
	t.Helper()
	var out []string
	for path, item := range openapi.Build("test", "").Paths {
		for method, op := range item.Operations() {
			for _, p := range op.Parameters {
				if p.Name == "user" && p.In == "query" {
					out = append(out, method+" "+path)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestV1SpecDocumentsUserParamExactlyWhereItWorks is the guard issue #293 was
// filed about. GET /entries advertised `user` and handed out ids that
// GET /entries/{id} then 404'd on, because only one of the pair called
// resolveTarget. Nothing connected the two sides, so nothing noticed.
//
// This connects them: the set of operations documenting `user` must be exactly
// the set of endpoints exercised above, which are exactly the ones that route
// through resolveTarget.
func TestV1SpecDocumentsUserParamExactlyWhereItWorks(t *testing.T) {
	var want []string
	for _, ep := range linkedReadHandlers {
		want = append(want, ep.name)
	}
	sort.Strings(want)

	got := specGETsWithUserParam(t)

	inWant := map[string]bool{}
	for _, w := range want {
		inWant[w] = true
	}
	inGot := map[string]bool{}
	for _, g := range got {
		inGot[g] = true
	}

	for _, g := range got {
		if !inWant[g] {
			t.Errorf("%s documents ?user= but does not route through resolveTarget — "+
				"the parameter would be silently ignored, or worse, honoured without an "+
				"authorization check", g)
		}
	}
	for _, w := range want {
		if !inGot[w] {
			t.Errorf("%s honours ?user= but the OpenAPI document does not mention it — "+
				"add linkedUserParam in internal/openapi/spec.go", w)
		}
	}
}

// TestV1SelfOnlyReadsSayWhyTheyAreSelfOnly covers the other half of #293: two
// read endpoints deliberately have no ?user= because no share category covers
// their data. An absent parameter is indistinguishable from an oversight, so
// the reason has to be written down where a reader of the spec will find it.
func TestV1SelfOnlyReadsSayWhyTheyAreSelfOnly(t *testing.T) {
	doc := openapi.Build("test", "")
	for _, path := range []string{"/saved-foods", "/plan"} {
		item, ok := doc.Paths[path]
		if !ok || item.Get == nil {
			t.Fatalf("GET %s is missing from the document", path)
		}
		desc := item.Get.Description
		if !strings.Contains(desc, "`user`") {
			t.Errorf("GET %s has no ?user= support and does not say so in its description — "+
				"the omission reads as an oversight", path)
		}
		if !strings.Contains(desc, "deliberately") {
			t.Errorf("GET %s should state that being self-only is a decision, not an accident "+
				"(description: %q)", path, desc)
		}
	}
}

// --- Integration ----------------------------------------------------------
//
// resolveTarget's allow decision is a SQL query against account_links, so the
// paths that matter most — accepted-and-shared, accepted-but-not-shared,
// pending, and not linked at all — cannot be exercised without a database.
//
// Skipped unless TEST_DATABASE_URL is set, matching internal/database's
// integration tests:
//
//	TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' \
//	  go test ./internal/handler/ -run TestV1LinkedAccountReads -v

// linkedFixture is a seeded caller, a data owner, and a stranger.
type linkedFixture struct {
	pool    *pgxpool.Pool
	handler *V1Handler
	caller  *model.User
	owner   *model.User
	// stranger has no link to the caller at all.
	stranger *model.User
	// entryID and entryDate belong to owner.
	entryID   int
	entryDate string
	token     *model.APIToken
}

func newLinkedFixture(t *testing.T) *linkedFixture {
	t.Helper()

	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	// database.NewPool, not pgxpool.New: the pool's AfterConnect hook installs
	// the codec that scans DATE as "YYYY-MM-DD" into a string. Every v1 read
	// struct here has a string Date, so a bare pgxpool would fail these tests
	// with a driver error that says nothing about the code under test.
	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	const (
		callerEmail   = "linked-reads-caller@handler.test"
		ownerEmail    = "linked-reads-owner@handler.test"
		strangerEmail = "linked-reads-stranger@handler.test"
	)
	emails := []string{callerEmail, ownerEmail, strangerEmail}
	cleanup := func() {
		for _, e := range emails {
			pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, e)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	seedUser := func(email, tz, unit string) *model.User {
		t.Helper()
		var id int
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (email, password_hash, email_verified, timezone, weight_unit, notes_enabled)
			 VALUES ($1, 'x', true, $2, $3, true) RETURNING id`, email, tz, unit).Scan(&id); err != nil {
			t.Fatalf("seeding %s failed: %v", email, err)
		}
		return &model.User{ID: id, Email: email, Timezone: &tz, WeightUnit: unit}
	}

	f := &linkedFixture{pool: pool}
	f.caller = seedUser(callerEmail, "Europe/Berlin", "kg")
	// The owner is on a different zone AND a different unit, so a handler that
	// rendered the caller's zone or mislabelled the unit shows up as a wrong
	// value rather than as a coincidence.
	f.owner = seedUser(ownerEmail, "America/New_York", "lb")
	f.stranger = seedUser(strangerEmail, "UTC", "kg")

	f.entryDate = "2026-08-05"
	if err := pool.QueryRow(ctx,
		`INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name)
		 VALUES ($1, $2, 450, 'Porridge') RETURNING id`, f.owner.ID, f.entryDate).Scan(&f.entryID); err != nil {
		t.Fatalf("seeding the owner's entry failed: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO weight_entries (user_id, entry_date, weight) VALUES ($1, $2, 181.2)`,
		f.owner.ID, f.entryDate); err != nil {
		t.Fatalf("seeding the owner's weight failed: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO todos (user_id, name, schedule) VALUES ($1, 'Owner walks the dog', '{"type":"daily"}')`,
		f.owner.ID); err != nil {
		t.Fatalf("seeding the owner's todo failed: %v", err)
	}

	f.handler = &V1Handler{Pool: pool}
	f.token = &model.APIToken{ID: 1, UserID: f.caller.ID, Scopes: service.AllScopes()}
	return f
}

// link writes (or rewrites) the caller↔owner link with the given status and
// the categories the OWNER shares with the caller.
func (f *linkedFixture) link(t *testing.T, status string, shares map[string]bool) {
	t.Helper()
	ctx := context.Background()
	raw, err := json.Marshal(shares)
	if err != nil {
		t.Fatalf("marshal shares: %v", err)
	}
	if _, err := f.pool.Exec(ctx,
		`DELETE FROM account_links WHERE requester_id = ANY($1) AND target_id = ANY($1)`,
		[]int{f.caller.ID, f.owner.ID}); err != nil {
		t.Fatalf("clearing the link failed: %v", err)
	}
	// The caller is the requester, so what the OWNER shares lives in
	// target_shares — the column resolveTarget reads for this direction.
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO account_links (requester_id, target_id, status, requester_shares, target_shares)
		 VALUES ($1, $2, $3, '{}'::jsonb, $4::jsonb)`,
		f.caller.ID, f.owner.ID, status, string(raw)); err != nil {
		t.Fatalf("seeding the link failed: %v", err)
	}
}

func (f *linkedFixture) get(ep linkedReadEndpoint, query string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ep.call(f.handler, rec, v1ReadRequest("/"+query, ep.params, f.caller, f.token))
	return rec
}

// allShared is every category on.
var allShared = map[string]bool{
	service.ShareNutrition: true, service.ShareWeight: true,
	service.ShareTodos: true, service.ShareNotes: true,
}

// TestV1LinkedAccountReadsAllowed covers the happy path for each newly-enabled
// endpoint, and in particular the list-then-fetch round trip that #293 reported
// as broken.
func TestV1LinkedAccountReadsAllowed(t *testing.T) {
	f := newLinkedFixture(t)
	f.link(t, "accepted", allShared)

	userQ := fmt.Sprintf("?user=%d", f.owner.ID)

	// The bug, end to end: list the owner's entries, then fetch one by the id
	// the list just returned.
	t.Run("list then fetch an entry", func(t *testing.T) {
		rec := f.get(linkedReadHandlers[0], userQ) // GET /entries
		if rec.Code != http.StatusOK {
			t.Fatalf("list: status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
		}
		var list struct {
			Data []v1Entry `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatalf("list body: %v", err)
		}
		if len(list.Data) != 1 || list.Data[0].ID != f.entryID {
			t.Fatalf("list returned %+v, want the owner's entry %d", list.Data, f.entryID)
		}

		ep := linkedReadEndpoint{
			name:   "GET /entries/{id}",
			params: map[string]string{"id": fmt.Sprint(list.Data[0].ID)},
			call:   func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.GetEntryV1(w, r) },
		}
		rec = f.get(ep, userQ)
		if rec.Code != http.StatusOK {
			t.Fatalf("fetch by the id the list handed out: status = %d, want 200 (body %q) — "+
				"this is the #293 dead end", rec.Code, rec.Body.String())
		}
		var got v1Entry
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("entry body: %v", err)
		}
		if got.ID != f.entryID || got.Calories != 450 {
			t.Errorf("entry = %+v, want id %d and 450 kcal", got, f.entryID)
		}
	})

	// Without ?user= the same id belongs to nobody the caller can see. 404,
	// not the caller's own row, and not someone else's data.
	t.Run("the same id without user is 404", func(t *testing.T) {
		ep := linkedReadEndpoint{
			params: map[string]string{"id": fmt.Sprint(f.entryID)},
			call:   func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.GetEntryV1(w, r) },
		}
		rec := f.get(ep, "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404 (body %q)", rec.Code, rec.Body.String())
		}
	})

	t.Run("weight by date", func(t *testing.T) {
		ep := linkedReadEndpoint{
			params: map[string]string{"date": f.entryDate},
			call:   func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.GetWeightV1(w, r) },
		}
		rec := f.get(ep, userQ)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
		}
		var got v1Weight
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("weight body: %v", err)
		}
		if got.Weight != 181.2 {
			t.Errorf("weight = %v, want 181.2", got.Weight)
		}
		// The owner records in lb, the caller in kg. Reporting the caller's
		// unit here would relabel 181.2 lb as 181.2 kg.
		if got.Unit != "lb" {
			t.Errorf("unit = %q, want %q (the OWNER's unit — readings are never converted)", got.Unit, "lb")
		}
	})

	t.Run("todo definitions", func(t *testing.T) {
		rec := f.get(linkedReadHandlers[4], userQ) // GET /todos
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
		}
		var list struct {
			Data []v1Todo `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatalf("todos body: %v", err)
		}
		if len(list.Data) != 1 || list.Data[0].Name != "Owner walks the dog" {
			t.Errorf("todos = %+v, want the owner's single todo", list.Data)
		}
	})
}

// TestV1LinkedAccountReadsDenied is the security half: every way the link can
// fail must produce 403 and no data, on every newly-enabled endpoint.
//
// 403 rather than 404 throughout, deliberately: a 404 that varied with whether
// the account existed would turn these endpoints into a user-id oracle.
func TestV1LinkedAccountReadsDenied(t *testing.T) {
	f := newLinkedFixture(t)

	// Only the newly-enabled endpoints; the pre-existing four already had
	// coverage of nothing, but their allow/deny path is the same call.
	endpoints := []linkedReadEndpoint{
		{"GET /entries/{id}", map[string]string{"id": fmt.Sprint(f.entryID)},
			func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.GetEntryV1(w, r) }},
		{"GET /weight/{date}", map[string]string{"date": f.entryDate},
			func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.GetWeightV1(w, r) }},
		{"GET /todos", nil,
			func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.ListTodosV1(w, r) }},
	}

	cases := []struct {
		name  string
		setup func()
		// target is whose data the caller asks for.
		target func() int
	}{
		{
			name:   "no link at all",
			setup:  func() {},
			target: func() int { return f.stranger.ID },
		},
		{
			name:   "link is still pending",
			setup:  func() { f.link(t, "pending", allShared) },
			target: func() int { return f.owner.ID },
		},
		{
			name:   "accepted but the category is off",
			setup:  func() { f.link(t, "accepted", map[string]bool{}) },
			target: func() int { return f.owner.ID },
		},
		{
			name: "accepted but only an unrelated category is shared",
			// notes only — none of the three endpoints under test reads notes.
			setup:  func() { f.link(t, "accepted", map[string]bool{service.ShareNotes: true}) },
			target: func() int { return f.owner.ID },
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.setup()
			q := fmt.Sprintf("?user=%d", c.target())
			for _, ep := range endpoints {
				rec := f.get(ep, q)
				if rec.Code != http.StatusForbidden {
					t.Errorf("%s: status = %d, want 403 (body %q)", ep.name, rec.Code, rec.Body.String())
					continue
				}
				// Nothing about the other account may leak into the body.
				if body := rec.Body.String(); strings.Contains(body, "Porridge") ||
					strings.Contains(body, "181.2") || strings.Contains(body, "Owner walks the dog") {
					t.Errorf("%s: denial response leaked the owner's data: %s", ep.name, body)
				}
			}
		})
	}
}

// A pending link must not become readable just because the caller happens to
// be the target rather than the requester. The share columns are directional
// and the status check has to hold in both directions.
func TestV1PendingLinkDeniedInBothDirections(t *testing.T) {
	f := newLinkedFixture(t)
	ctx := context.Background()

	// Owner requests, caller is the target — the mirror of fixture.link.
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO account_links (requester_id, target_id, status, requester_shares, target_shares)
		 VALUES ($1, $2, 'pending', $3::jsonb, '{}'::jsonb)`,
		f.owner.ID, f.caller.ID, `{"nutrition":true,"weight":true,"todos":true,"notes":true}`); err != nil {
		t.Fatalf("seeding the reversed link failed: %v", err)
	}

	ep := linkedReadEndpoint{
		params: map[string]string{"id": fmt.Sprint(f.entryID)},
		call:   func(h *V1Handler, w http.ResponseWriter, r *http.Request) { h.GetEntryV1(w, r) },
	}
	rec := f.get(ep, fmt.Sprintf("?user=%d", f.owner.ID))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — a pending request is not consent (body %q)",
			rec.Code, rec.Body.String())
	}
}

// Naming your own id is not a cross-account read and must not require
// links:read — a token with entries:read alone should still work.
func TestV1SelfUserParamNeedsNoLinksScope(t *testing.T) {
	f := newLinkedFixture(t)

	f.token = &model.APIToken{ID: 1, UserID: f.caller.ID, Scopes: []string{service.ScopeEntriesRead}}
	ep := linkedReadHandlers[0] // GET /entries
	rec := f.get(ep, fmt.Sprintf("?user=%d", f.caller.ID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
}
