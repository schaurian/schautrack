package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/apierr"
	"schautrack/internal/database"
	"schautrack/internal/openapi"
	"schautrack/internal/service"
)

// Shared harness for the DB-backed /api/v1 behaviour tests.
//
// The structural guards (v1_spec_test.go, v1_contract_test.go,
// v1_optional_test.go) prove the route table, the response shapes and the
// PATCH decoder are consistent. None of them sends a request to an endpoint,
// so every apierr.* branch in the handlers was unexecuted. These tests build
// the REAL router via MountAPIV1, mint a REAL token through
// service.CreateAPIToken, and drive it with httptest against a real Postgres.
//
// Skipped unless TEST_DATABASE_URL is set, matching internal/database's
// integration tests and internal/handler/onboarding_test.go.

var (
	v1PoolOnce sync.Once
	v1Pool     *pgxpool.Pool
	v1PoolErr  error
)

// v1TestPool returns a process-wide pool with the schema applied. It is shared
// rather than per-test because InitSchemaWithRetry replays every migration,
// which is far too slow to repeat once per test function.
func v1TestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	v1PoolOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		// database.NewPool, not pgxpool.New: the app registers a codec that
		// scans DATE columns straight into string, and every v1 handler relies
		// on it (v1Entry.Date, v1Weight.Date, …). A plain pool makes each of
		// them 500 on a scan error — which is a property of the harness, not of
		// the handler, so the harness must build the pool the way cmd/server
		// does.
		pool, err := database.NewPool(ctx, url)
		if err != nil {
			v1PoolErr = fmt.Errorf("pool: %w", err)
			return
		}
		if err := database.InitSchemaWithRetry(ctx, pool, 3); err != nil {
			v1PoolErr = fmt.Errorf("migrations: %w", err)
			return
		}
		v1Pool = pool
	})
	if v1PoolErr != nil {
		t.Fatalf("test database setup failed: %v", v1PoolErr)
	}
	return v1Pool
}

// v1Env is one test's world: a pool, a freshly seeded user, and the real
// router mounted where it lives in production.
type v1Env struct {
	t      *testing.T
	Pool   *pgxpool.Pool
	Router http.Handler
	Ctx    context.Context

	UserID int
	Email  string

	// tokens memoises by scope set. service.MaxTokensPerUser caps an account at
	// 20 live tokens, and a table over ~28 routes would blow through that in a
	// single test if every case minted its own.
	tokens map[string]string
}

// newV1Env seeds a user and mounts /api/v1 exactly as cmd/server does, so the
// paths under test are the paths clients use and Location headers can be
// followed verbatim.
func newV1Env(t *testing.T) *v1Env {
	t.Helper()
	pool := v1TestPool(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	e := &v1Env{t: t, Pool: pool, Ctx: ctx, tokens: map[string]string{}}
	e.UserID, e.Email = e.seedUser("")

	h := &V1Handler{Pool: pool, BuildVersion: "v1-integration-test"}
	r := chi.NewRouter()
	r.Mount("/api/v1", h.MountAPIV1(pool))
	e.Router = r

	return e
}

// seedUser inserts an account whose email is derived from the test name, so
// concurrent packages and reruns cannot collide and a leftover row from a
// crashed run is always overwritten.
func (e *v1Env) seedUser(suffix string) (int, string) {
	e.t.Helper()

	slug := strings.NewReplacer("/", "-", " ", "-", "#", "-").Replace(e.t.Name())
	email := strings.ToLower(slug) + suffix + "@v1.integration.test"

	del := func() {
		if _, err := e.Pool.Exec(context.Background(),
			`DELETE FROM users WHERE email = $1`, email); err != nil {
			e.t.Logf("cleanup of %s failed: %v", email, err)
		}
	}
	del()
	e.t.Cleanup(del)

	// notes_enabled is on so the notes endpoints reach their own validation
	// instead of short-circuiting on the feature flag; the 409 that flag
	// produces has its own test.
	var id int
	if err := e.Pool.QueryRow(e.Ctx, `
		INSERT INTO users (email, password_hash, email_verified, timezone, notes_enabled)
		VALUES ($1, 'x', true, 'UTC', true) RETURNING id`, email).Scan(&id); err != nil {
		e.t.Fatalf("seeding user %s failed: %v", email, err)
	}
	return id, email
}

// token returns a real API token for the env's user, minting one per distinct
// scope set and reusing it thereafter.
func (e *v1Env) token(scopes ...string) string {
	e.t.Helper()

	key := strings.Join(scopes, ",")
	if raw, ok := e.tokens[key]; ok {
		return raw
	}
	raw := e.tokenFor(e.UserID, scopes...)
	e.tokens[key] = raw
	return raw
}

func (e *v1Env) tokenFor(userID int, scopes ...string) string {
	e.t.Helper()
	_, raw, err := service.CreateAPIToken(e.Ctx, e.Pool, userID,
		fmt.Sprintf("test-%d", time.Now().UnixNano()), scopes, nil)
	if err != nil {
		e.t.Fatalf("minting a token with scopes %v failed: %v", scopes, err)
	}
	return raw
}

// allScopesToken carries every grantable scope — used where the point of the
// test is the endpoint's own validation rather than authorization.
func (e *v1Env) allScopesToken() string {
	e.t.Helper()
	return e.token(service.AllScopes()...)
}

// call is one request. Token "" sends no Authorization header at all, which is
// the anonymous case rather than a malformed one.
type call struct {
	Method  string
	Path    string
	Token   string
	Body    string
	Headers map[string]string
}

func (e *v1Env) do(c call) *httptest.ResponseRecorder {
	e.t.Helper()

	var body *strings.Reader
	if c.Body != "" {
		body = strings.NewReader(c.Body)
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(c.Method, c.Path, body)
	req = req.WithContext(e.Ctx)
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if c.Body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	e.Router.ServeHTTP(rec, req)
	return rec
}

// get / post / patch / put / del are thin conveniences over do.
func (e *v1Env) get(path, token string) *httptest.ResponseRecorder {
	return e.do(call{Method: http.MethodGet, Path: path, Token: token})
}

func (e *v1Env) post(path, token, body string) *httptest.ResponseRecorder {
	return e.do(call{Method: http.MethodPost, Path: path, Token: token, Body: body})
}

func (e *v1Env) patch(path, token, body string) *httptest.ResponseRecorder {
	return e.do(call{Method: http.MethodPatch, Path: path, Token: token, Body: body})
}

// mustRequest builds a bare *http.Request, used where a test needs to compute
// something the middleware would compute (e.g. an idempotency fingerprint)
// without sending anything.
func mustRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	return httptest.NewRequest(method, path, strings.NewReader(body))
}

// --- Assertions -----------------------------------------------------------

// requireProblem asserts the response is an RFC 9457 problem with the expected
// status, and returns it. Invariant #3 of the API contract ("errors are
// problem+json, always") is checked on every single error path this way.
func requireProblem(t *testing.T, rec *httptest.ResponseRecorder, want int) apierr.Problem {
	t.Helper()

	if rec.Code != want {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, want, rec.Body.String())
	}
	return requireProblemShape(t, rec)
}

// requireProblemShape checks the problem+json content type and envelope
// without pinning the status.
func requireProblemShape(t *testing.T, rec *httptest.ResponseRecorder) apierr.Problem {
	t.Helper()

	if ct := rec.Header().Get("Content-Type"); ct != apierr.ContentType {
		t.Errorf("Content-Type = %q, want %q (body: %s)", ct, apierr.ContentType, rec.Body.String())
	}
	var p apierr.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("error body is not JSON: %v (body: %s)", err, rec.Body.String())
	}
	if p.Type == "" {
		t.Errorf("problem has no type field: %s", rec.Body.String())
	}
	if p.Title == "" {
		t.Errorf("problem has no title field: %s", rec.Body.String())
	}
	if p.Status != rec.Code {
		t.Errorf("problem.status = %d but the HTTP status is %d; a client branching on the body would disagree with one branching on the status",
			p.Status, rec.Code)
	}
	return p
}

// decodeJSON unmarshals a success body into dst.
func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("response is not JSON: %v (body: %s)", err, rec.Body.String())
	}
}

// requireSchema validates a success body against the schema the published
// OpenAPI document declares for it, so a behaviour test also catches drift.
func requireSchema(t *testing.T, rec *httptest.ResponseRecorder, schema string) {
	t.Helper()
	if err := openapi.Build("test", "").ValidateJSON(schema, rec.Body.Bytes()); err != nil {
		t.Errorf("response does not match the documented %s schema: %v\n\nbody: %s",
			schema, err, rec.Body.String())
	}
}

// --- Route table ----------------------------------------------------------

// v1Route is one served endpoint plus the scope guarding it.
type v1Route struct {
	Method  string
	Pattern string // chi pattern, e.g. /entries/{id}
	Scope   string // "" = any valid token
}

// v1Routes enumerates the endpoints from the REAL chi router, joined with the
// scope each one declares in the OpenAPI document.
//
// Driving the tables off chi.Walk rather than a hand-written list is what makes
// them a guard: a route added to MountAPIV1 tomorrow is covered by every table
// in this package without anyone remembering to extend a list. (The spec is the
// scope source because the router does not expose its middleware; the two are
// kept in lockstep by TestV1RoutesMatchSpec.)
func v1Routes(t *testing.T) []v1Route {
	t.Helper()

	scopes := map[string]string{}
	documented := map[string]bool{}
	for _, op := range openapi.Build("test", "").Operations() {
		scopes[op.Method+" "+op.Path] = op.Scope
		documented[op.Method+" "+op.Path] = true
	}

	var out []v1Route
	h := &V1Handler{}
	if err := chi.Walk(h.MountAPIV1(nil), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.TrimSuffix(route, "/")
		if route == "" {
			route = "/"
		}
		if route == "/openapi.json" {
			return nil // public by design; it has its own test
		}
		key := method + " " + route
		if !documented[key] {
			t.Errorf("route %s is served but undocumented; TestV1RoutesMatchSpec should have caught this", key)
			return nil
		}
		out = append(out, v1Route{Method: method, Pattern: route, Scope: scopes[key]})
		return nil
	}); err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("no v1 routes discovered — the walk is broken, not the router")
	}
	return out
}

// pathParams are the concrete values substituted into a chi pattern.
//
// Deliberately exhaustive: an unknown parameter fails the test rather than
// being skipped, so adding /api/v1/{thing}/{newparam} forces a decision about
// what a valid value looks like instead of silently dropping coverage.
var pathParams = map[string]string{
	"{id}":   "1",
	"{date}": "2026-08-05",
	"{code}": "4006381333931",
}

func concretePath(t *testing.T, pattern string) string {
	t.Helper()

	out := pattern
	for name, value := range pathParams {
		out = strings.ReplaceAll(out, name, value)
	}
	if strings.ContainsAny(out, "{}") {
		t.Fatalf("route %s has a path parameter with no test value; add one to pathParams", pattern)
	}
	return "/api/v1" + out
}

// hasBody reports whether a method carries a request body the handlers decode.
func (r v1Route) hasBody() bool {
	switch r.Method {
	case http.MethodPost, http.MethodPatch, http.MethodPut:
		return true
	}
	return false
}

// otherScope returns a grantable scope that does NOT satisfy r.Scope, for the
// "wrong scope must 403" case. It returns "" when the route needs no scope.
func (r v1Route) otherScope() string {
	if r.Scope == "" {
		return ""
	}
	for _, s := range service.AllScopes() {
		if !service.ScopeSatisfies([]string{s}, r.Scope) {
			return s
		}
	}
	return ""
}

func (r v1Route) String() string { return r.Method + " " + r.Pattern }
