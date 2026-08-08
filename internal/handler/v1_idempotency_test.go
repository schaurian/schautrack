package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/database"
	"schautrack/internal/openapi"
	"schautrack/internal/service"
)

// --- What the route table promises ---------------------------------------

// idempotencyRejectingPosts lists the POST routes that deliberately do NOT
// honour Idempotency-Key and answer 400 when it is sent.
//
// Every other POST must honour it. There is no third option: an unwrapped POST
// accepts the header and ignores it, and because an unknown header — unlike an
// unknown body field — is rejected nowhere, the caller reads the 201 as
// retry-safety it does not have.
var idempotencyRejectingPosts = map[string]bool{
	// Not a create, and not replayable today: the estimate is billed per call
	// and produced by the app's own handler. Honouring the header here is a
	// feature, not a bug fix; until then it says so rather than pretending.
	"POST /ai/estimate": true,
}

// specIdempotentRoutes returns the routes whose OpenAPI entry declares the
// Idempotency-Key header — the client-visible half of the same promise.
func specIdempotentRoutes(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for path, item := range openapi.Build("test", "").Paths {
		for method, op := range item.Operations() {
			for _, p := range op.Parameters {
				if p.In == "header" && p.Name == "Idempotency-Key" {
					out[method+" "+path] = true
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("no operation declares Idempotency-Key — the spec walk is broken, not the spec")
	}
	return out
}

func postRoutes(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, r := range walkV1Routes(t) {
		if strings.HasPrefix(r, http.MethodPost+" ") {
			out = append(out, r)
		}
	}
	return out
}

// TestEveryV1PostDecidesOnIdempotencyKey is the guard that stops this class of
// bug from recurring.
//
// POST /todos and POST /saved-foods shipped unwrapped: they created a resource,
// accepted an Idempotency-Key, and did nothing with it. Nothing failed — not
// the route-parity test, not the client — until a timed-out request was retried
// and produced a duplicate. So the decision is made explicit here: a new POST
// route either declares the header in the spec (and is wrapped in
// withIdempotency) or is listed as rejecting it. Adding one that does neither
// fails the build.
func TestEveryV1PostDecidesOnIdempotencyKey(t *testing.T) {
	honoured := specIdempotentRoutes(t)

	for _, route := range postRoutes(t) {
		switch {
		case honoured[route] && idempotencyRejectingPosts[route]:
			t.Errorf("%s is listed as both honouring and rejecting Idempotency-Key", route)
		case honoured[route], idempotencyRejectingPosts[route]:
			// Decided, either way.
		default:
			t.Errorf("%s creates something but neither honours nor rejects Idempotency-Key.\n"+
				"Wrap it in withIdempotency and add idempotencyParam to its spec entry, or wrap it in "+
				"rejectIdempotencyKey and list it in idempotencyRejectingPosts. Leaving it unwrapped means "+
				"a client that sends the header gets a 201 and a duplicate on retry.", route)
		}
	}

	served := map[string]bool{}
	for _, r := range postRoutes(t) {
		served[r] = true
	}
	for route := range honoured {
		if !served[route] {
			t.Errorf("the spec declares Idempotency-Key on %s, which is not a served POST route", route)
		}
	}
	for route := range idempotencyRejectingPosts {
		if !served[route] {
			t.Errorf("idempotencyRejectingPosts names %s, which is not a served POST route", route)
		}
	}
}

// TestRejectIdempotencyKeyAnswersBeforeTheHandlerRuns pins the ordering that
// makes the rejection honest. Refusing after the work is done would report a
// failure for a request that actually succeeded — worse than ignoring it.
func TestRejectIdempotencyKeyAnswersBeforeTheHandlerRuns(t *testing.T) {
	ran := false
	guarded := rejectIdempotencyKey(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.WriteHeader(http.StatusCreated)
	})

	req := httptest.NewRequest(http.MethodPost, "/ai/estimate", strings.NewReader(`{}`))
	req.Header.Set("Idempotency-Key", "probe")
	rec := httptest.NewRecorder()
	guarded(rec, req)

	if ran {
		t.Error("the handler ran; the header must be refused before any work is done")
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}

	// Without the header the handler must run exactly as before.
	ran = false
	rec = httptest.NewRecorder()
	guarded(rec, httptest.NewRequest(http.MethodPost, "/ai/estimate", strings.NewReader(`{}`)))
	if !ran {
		t.Error("the handler did not run without the header; the guard must be a no-op then")
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201", rec.Code)
	}
}

// --- Integration: the header actually works ------------------------------

// idemHarness is a real router, a real user, and a real token, so the tests
// below exercise the whole chain — auth, scope, wrapper, handler, database —
// rather than a handler called in isolation. The bug being fixed was in the
// wiring, so testing the wiring is the point.
type idemHarness struct {
	pool   *pgxpool.Pool
	router http.Handler
	token  string
	userID int
	ctx    context.Context
}

func newIdemHarness(t *testing.T, email string) *idemHarness {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	// database.NewPool, not pgxpool.New: it registers the codec that scans
	// DATE columns as "YYYY-MM-DD" strings, which every entry query relies on.
	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	cleanup := func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, email) }
	cleanup()
	t.Cleanup(cleanup)

	var userID int
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, email_verified) VALUES ($1, 'x', true) RETURNING id`,
		email).Scan(&userID); err != nil {
		t.Fatalf("seeding the user failed: %v", err)
	}

	_, raw, err := service.CreateAPIToken(ctx, pool, userID, "idempotency test", []string{
		service.ScopeEntriesRead, service.ScopeEntriesWrite,
		service.ScopeTodosRead, service.ScopeTodosWrite,
		service.ScopeFoodsRead, service.ScopeFoodsWrite,
		service.ScopeAIEstimate,
	}, nil)
	if err != nil {
		t.Fatalf("minting a token failed: %v", err)
	}

	h := &V1Handler{Pool: pool}
	return &idemHarness{pool: pool, router: h.MountAPIV1(pool), token: raw, userID: userID, ctx: ctx}
}

// post sends a POST with the given key (empty means no header).
func (hh *idemHarness) post(t *testing.T, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+hh.token)
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	rec := httptest.NewRecorder()
	hh.router.ServeHTTP(rec, req)
	return rec
}

func (hh *idemHarness) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := hh.pool.QueryRow(hh.ctx,
		"SELECT COUNT(*)::int FROM "+table+" WHERE user_id = $1", hh.userID).Scan(&n); err != nil {
		t.Fatalf("counting %s: %v", table, err)
	}
	return n
}

// TestIdempotentPostsReplayInsteadOfDuplicating covers every POST the spec says
// honours the header, so a route added later is exercised too rather than
// merely listed.
//
// Identical response bytes are the assertion that matters: a second create
// would return a new server-assigned id, so a byte-identical body cannot be a
// second row.
func TestIdempotentPostsReplayInsteadOfDuplicating(t *testing.T) {
	hh := newIdemHarness(t, "idempotency-replay@handler.test")

	// A saved food to track, for the /saved-foods/{id}/track fixture.
	rec := hh.post(t, "/saved-foods", "", `{"name":"Fixture food","calories":120}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seeding a saved food: status = %d, body %s", rec.Code, rec.Body.String())
	}
	var seeded struct {
		ID int `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &seeded); err != nil {
		t.Fatalf("seeded food is not JSON: %v", err)
	}

	// A valid body for each idempotent POST. A new idempotent route with no
	// fixture fails the test below rather than silently going uncovered.
	fixtures := map[string]struct{ path, body string }{
		"POST /entries":                {"/entries", `{"calories":250,"name":"Replay probe"}`},
		"POST /todos":                  {"/todos", `{"name":"Replay probe","schedule":{"type":"daily"}}`},
		"POST /saved-foods":            {"/saved-foods", `{"name":"Replay probe food","calories":95}`},
		"POST /saved-foods/{id}/track": {"/saved-foods/" + strconv.Itoa(seeded.ID) + "/track", `{}`},
	}

	for route := range specIdempotentRoutes(t) {
		fx, ok := fixtures[route]
		if !ok {
			t.Errorf("%s honours Idempotency-Key but has no request fixture here — add one so the "+
				"replay is actually verified", route)
			continue
		}
		t.Run(route, func(t *testing.T) {
			key := "replay-" + strings.ReplaceAll(route, " ", "-")

			first := hh.post(t, fx.path, key, fx.body)
			if first.Code < 200 || first.Code > 299 {
				t.Fatalf("first request: status = %d, want 2xx (body %s)", first.Code, first.Body.String())
			}
			if first.Header().Get("Idempotency-Replayed") != "" {
				t.Error("the first request was marked as a replay")
			}

			second := hh.post(t, fx.path, key, fx.body)
			if second.Code != first.Code {
				t.Fatalf("retry: status = %d, want %d (body %s)", second.Code, first.Code, second.Body.String())
			}
			if second.Header().Get("Idempotency-Replayed") != "true" {
				t.Error("retry is missing Idempotency-Replayed: true, so the client cannot tell " +
					"a replay from a second create")
			}
			if got, want := second.Body.String(), first.Body.String(); got != want {
				t.Errorf("retry created a second resource.\n first: %s\nsecond: %s", want, got)
			}
			if got, want := second.Header().Get("Location"), first.Header().Get("Location"); got != want {
				t.Errorf("retry Location = %q, want %q", got, want)
			}
		})
	}

	// The two endpoints this issue is about, counted directly: the response
	// comparison above proves no new id was minted, this proves no row was.
	if n := hh.count(t, "todos"); n != 1 {
		t.Errorf("todos rows = %d, want 1 — the retry double-created", n)
	}
	if n := hh.count(t, "saved_foods"); n != 2 {
		t.Errorf("saved_foods rows = %d, want 2 (the fixture food and one probe)", n)
	}
}

// TestIdempotencyKeyReusedForADifferentBodyIs409 covers the case that makes
// replaying safe to trust: the same key with different content is a client
// mistake, and answering 201 with the ORIGINAL todo would silently discard what
// was just asked for.
func TestIdempotencyKeyReusedForADifferentBodyIs409(t *testing.T) {
	hh := newIdemHarness(t, "idempotency-mismatch@handler.test")

	const key = "recycled-key"
	if rec := hh.post(t, "/todos", key, `{"name":"First","schedule":{"type":"daily"}}`); rec.Code != http.StatusCreated {
		t.Fatalf("first todo: status = %d, body %s", rec.Code, rec.Body.String())
	}

	rec := hh.post(t, "/todos", key, `{"name":"Different","schedule":{"type":"daily"}}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	if n := hh.count(t, "todos"); n != 1 {
		t.Errorf("todos rows = %d, want 1 — the mismatched retry must create nothing", n)
	}
}

// TestFailedRequestReleasesTheIdempotencyKey covers the release path.
//
// The key is claimed BEFORE the handler runs, which is what makes two
// concurrent retries safe. The cost is that a request which then fails has
// burned a key the client is going to reuse: without the release, fixing the
// body and retrying would hit the fingerprint check and 409 forever, pinning
// the client to a mistake it had already corrected.
func TestFailedRequestReleasesTheIdempotencyKey(t *testing.T) {
	hh := newIdemHarness(t, "idempotency-release@handler.test")

	const key = "retry-after-failure"
	rec := hh.post(t, "/todos", key, `{"name":"   ","schedule":{"type":"daily"}}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid todo: status = %d, want 422 (body %s)", rec.Code, rec.Body.String())
	}

	var claims int
	if err := hh.pool.QueryRow(hh.ctx,
		`SELECT COUNT(*)::int FROM api_idempotency WHERE user_id = $1 AND idempotency_key = $2`,
		hh.userID, key).Scan(&claims); err != nil {
		t.Fatalf("counting claims: %v", err)
	}
	if claims != 0 {
		t.Errorf("the failed request left %d claim(s) behind; the corrected retry would 409 forever", claims)
	}

	rec = hh.post(t, "/todos", key, `{"name":"Corrected","schedule":{"type":"daily"}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("corrected retry: status = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Idempotency-Replayed") != "" {
		t.Error("the corrected retry was answered as a replay of the failure")
	}
	if n := hh.count(t, "todos"); n != 1 {
		t.Errorf("todos rows = %d, want 1", n)
	}
}

// TestUnsupportedIdempotencyKeyIsRejectedByTheRouter proves the guard is wired
// ahead of the handler on the one POST that does not honour the header: the
// same request without the header reaches the handler and 404s (no AI provider
// is configured here), so the 400 can only come from the guard.
func TestUnsupportedIdempotencyKeyIsRejectedByTheRouter(t *testing.T) {
	hh := newIdemHarness(t, "idempotency-unsupported@handler.test")

	rec := hh.post(t, "/ai/estimate", "some-key", `{"image":"x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	var p map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if detail, _ := p["detail"].(string); !strings.Contains(detail, "Idempotency-Key") {
		t.Errorf("detail = %q, want it to name the header so the client knows what to drop", detail)
	}

	if rec := hh.post(t, "/ai/estimate", "", `{"image":"x"}`); rec.Code == http.StatusBadRequest {
		t.Errorf("the same request without the header also 400s (body %s); "+
			"the rejection above proves nothing", rec.Body.String())
	}
}
