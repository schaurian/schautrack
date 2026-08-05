package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"schautrack/internal/openapi"
	"schautrack/internal/service"
)

// walkV1Routes returns every (method, path) the real /api/v1 router serves,
// with paths normalized to the OpenAPI style: chi renders parameters as
// {id} already, but appends a trailing slash to sub-router roots.
func walkV1Routes(t *testing.T) []string {
	t.Helper()

	// A zero-value handler is enough: chi.Walk only inspects the route tree,
	// it never calls a handler, so no database is required. This is exactly
	// why MountAPIV1 has to be constructible without one.
	h := &V1Handler{}
	router := h.MountAPIV1(nil)

	var routes []string
	err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		route = strings.TrimSuffix(route, "/")
		if route == "" {
			route = "/"
		}
		routes = append(routes, method+" "+route)
		return nil
	})
	if err != nil {
		t.Fatalf("chi.Walk: %v", err)
	}
	sort.Strings(routes)
	return routes
}

func specRoutes() []string {
	var out []string
	for _, op := range openapi.Build("test").Operations() {
		out = append(out, op.Method+" "+op.Path)
	}
	sort.Strings(out)
	return out
}

// TestV1RoutesMatchSpec is the guard that keeps the documentation honest.
//
// The old docs/api.md drifted because nothing connected it to the routes it
// described. This test connects them: add a route without a spec entry, or
// spec an endpoint that does not exist, and the build fails.
func TestV1RoutesMatchSpec(t *testing.T) {
	actual := walkV1Routes(t)
	documented := specRoutes()

	inSpec := map[string]bool{}
	for _, r := range documented {
		inSpec[r] = true
	}
	inRouter := map[string]bool{}
	for _, r := range actual {
		inRouter[r] = true
	}

	for _, r := range actual {
		if !inSpec[r] {
			t.Errorf("route %s is served but missing from the OpenAPI document — add it to internal/openapi/spec.go", r)
		}
	}
	for _, r := range documented {
		if !inRouter[r] {
			t.Errorf("route %s is documented but not served — remove it from internal/openapi/spec.go or add the route", r)
		}
	}
}

// TestV1SpecIsValidJSON checks the document marshals and round-trips.
func TestV1SpecIsValidJSON(t *testing.T) {
	raw, err := openapi.Build("test").JSON()
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("spec is not valid JSON: %v", err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Errorf("openapi = %v, want 3.1.0", doc["openapi"])
	}
	if _, ok := doc["paths"]; !ok {
		t.Error("spec has no paths object")
	}
}

// TestV1SpecRefsResolve checks every $ref points at a schema that exists. A
// dangling $ref renders as a blank box in every documentation viewer and
// breaks every client generator, silently.
func TestV1SpecRefsResolve(t *testing.T) {
	doc := openapi.Build("test")
	raw, err := doc.JSON()
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}

	defined := map[string]bool{}
	for name := range doc.Components.Schemas {
		defined[name] = true
	}

	var walk func(v any)
	seen := map[string]bool{}
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if ref, ok := t["$ref"].(string); ok {
				seen[ref] = true
			}
			for _, child := range t {
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	walk(parsed)

	if len(seen) == 0 {
		t.Fatal("no $refs found — the walk is broken, not the spec")
	}
	for ref := range seen {
		name, ok := strings.CutPrefix(ref, "#/components/schemas/")
		if !ok {
			t.Errorf("unexpected $ref form %q", ref)
			continue
		}
		if !defined[name] {
			t.Errorf("$ref %q points at a schema that is not defined", ref)
		}
	}
}

// TestV1SpecScopesAreReal checks every scope named in the document is one the
// server actually grants. A spec advertising `entries:readonly` would send
// users to mint tokens that can never work.
func TestV1SpecScopesAreReal(t *testing.T) {
	valid := map[string]bool{}
	for _, s := range service.AllScopes() {
		valid[s] = true
	}
	for _, op := range openapi.Build("test").Operations() {
		if op.Scope == "" {
			continue // /me and /openapi.json need no scope
		}
		if !valid[op.Scope] {
			t.Errorf("%s %s declares scope %q, which the server does not grant", op.Method, op.Path, op.Scope)
		}
	}
}

// TestV1SpecServedOverHTTP checks the endpoint returns the document without
// authentication — a client must be able to read the contract before it has a
// token.
func TestV1SpecServedOverHTTP(t *testing.T) {
	h := &V1Handler{BuildVersion: "test"}
	// The sub-router is exercised directly, so paths are relative to its own
	// root — /openapi.json here, /api/v1/openapi.json once mounted.
	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	rec := httptest.NewRecorder()

	h.MountAPIV1(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the spec must not require a token)", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/openapi+json") {
		t.Errorf("Content-Type = %q, want application/openapi+json", ct)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("served spec is not valid JSON: %v", err)
	}
}

// TestV1UnauthenticatedRequestsAreRejected checks that every scoped endpoint
// refuses an anonymous caller with problem+json, and that chi's own 404
// handler does too.
func TestV1UnauthenticatedRequestsAreRejected(t *testing.T) {
	h := &V1Handler{}
	router := h.MountAPIV1(nil)

	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/me", http.StatusUnauthorized},
		{http.MethodGet, "/entries", http.StatusUnauthorized},
		{http.MethodPost, "/entries", http.StatusUnauthorized},
		{http.MethodGet, "/weight/2026-08-05", http.StatusUnauthorized},
		{http.MethodGet, "/plan", http.StatusUnauthorized},
		{http.MethodGet, "/nope", http.StatusNotFound},
	}

	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)

		if rec.Code != c.want {
			t.Errorf("%s %s: status = %d, want %d", c.method, c.path, rec.Code, c.want)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Errorf("%s %s: Content-Type = %q, want application/problem+json", c.method, c.path, ct)
		}
		var p map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Errorf("%s %s: body is not JSON: %v", c.method, c.path, err)
			continue
		}
		if _, ok := p["type"]; !ok {
			t.Errorf("%s %s: problem has no type field", c.method, c.path)
		}
	}
}

// TestV1CookiesAreNotAccepted is the CSRF argument, asserted.
//
// The v1 surface has no CSRF protection because it accepts no ambient
// credentials. If a session cookie ever started authenticating a v1 request,
// that reasoning would silently become false — so it is a test, not a comment.
func TestV1CookiesAreNotAccepted(t *testing.T) {
	h := &V1Handler{}
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(&http.Cookie{Name: "schautrack.sid", Value: "a-perfectly-valid-looking-session"})
	rec := httptest.NewRecorder()

	h.MountAPIV1(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — a session cookie must never authenticate /api/v1", rec.Code)
	}
	if auth := rec.Header().Get("WWW-Authenticate"); !strings.Contains(auth, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want it to advertise Bearer", auth)
	}
}

// TestV1MethodNotAllowedIsProblemJSON checks chi's 405 is overridden too.
func TestV1MethodNotAllowedIsProblemJSON(t *testing.T) {
	h := &V1Handler{}
	req := httptest.NewRequest(http.MethodDelete, "/me", nil)
	rec := httptest.NewRecorder()

	h.MountAPIV1(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}
