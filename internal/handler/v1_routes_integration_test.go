package handler

import (
	"net/http"
	"strings"
	"testing"

	"schautrack/internal/service"
)

// The tables in this file are the ones the issue calls the "minimum first
// slice": for EVERY endpoint the router serves,
//
//  1. no token           → 401 problem+json
//  2. wrong scope        → 403 problem+json, naming the scope it wanted
//  3. a malformed body   → 4xx problem+json, and never 5xx
//  4. Content-Type is application/problem+json on every error path
//
// They are driven off chi.Walk (see v1Routes), so a route added to MountAPIV1
// is covered the moment it exists. That is the difference between a guard and
// a snapshot.

// TestV1EveryEndpointRejectsAnonymous covers invariant #1 (bearer tokens only)
// and #3 (problem+json errors) across the whole surface, rather than the five
// hand-picked paths TestV1UnauthenticatedRequestsAreRejected checks.
func TestV1EveryEndpointRejectsAnonymous(t *testing.T) {
	e := newV1Env(t)

	for _, rt := range v1Routes(t) {
		t.Run(rt.String(), func(t *testing.T) {
			rec := e.do(call{Method: rt.Method, Path: concretePath(t, rt.Pattern)})

			p := requireProblem(t, rec, http.StatusUnauthorized)
			if p.Detail == "" {
				t.Error("a 401 with no detail tells the caller nothing about how to authenticate")
			}
			if auth := rec.Header().Get("WWW-Authenticate"); auth == "" {
				t.Error("no WWW-Authenticate header; RFC 6750 §3 requires the scheme be advertised on a 401")
			}
		})
	}
}

// TestV1EveryEndpointRejectsAnInvalidToken checks a syntactically plausible but
// unknown token is refused the same way, rather than falling through to a
// handler with a nil user (which would panic into a 500).
func TestV1EveryEndpointRejectsAnInvalidToken(t *testing.T) {
	e := newV1Env(t)

	// Right shape, never minted.
	const bogus = "stk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	for _, rt := range v1Routes(t) {
		t.Run(rt.String(), func(t *testing.T) {
			rec := e.do(call{Method: rt.Method, Path: concretePath(t, rt.Pattern), Token: bogus})
			requireProblem(t, rec, http.StatusUnauthorized)
		})
	}
}

// TestV1EveryEndpointEnforcesItsScope is the assertion CLAUDE.md's scope table
// was making on trust. api-tokens.spec.ts checks scope enforcement on the two
// endpoints it happens to hit; this checks all of them.
func TestV1EveryEndpointEnforcesItsScope(t *testing.T) {
	e := newV1Env(t)

	for _, rt := range v1Routes(t) {
		if rt.Scope == "" {
			continue // GET /me deliberately needs only a valid token
		}
		t.Run(rt.String(), func(t *testing.T) {
			wrong := rt.otherScope()
			if wrong == "" {
				t.Fatalf("no grantable scope fails to satisfy %q — the test cannot distinguish", rt.Scope)
			}
			token := e.token(wrong)

			rec := e.do(call{
				Method: rt.Method, Path: concretePath(t, rt.Pattern), Token: token,
				Body: "{}",
			})

			p := requireProblem(t, rec, http.StatusForbidden)
			if p.RequiredScope != rt.Scope {
				t.Errorf("required_scope = %q, want %q; a client cannot tell the user which scope to add",
					p.RequiredScope, rt.Scope)
			}
		})
	}
}

// TestV1ScopeIsCheckedBeforeTheBodyIsRead guards the ordering: a token that may
// not touch an endpoint must be turned away before its payload is parsed, or a
// 400 would leak that the request WOULD have been valid.
func TestV1ScopeIsCheckedBeforeTheBodyIsRead(t *testing.T) {
	e := newV1Env(t)

	for _, rt := range v1Routes(t) {
		if rt.Scope == "" || !rt.hasBody() {
			continue
		}
		t.Run(rt.String(), func(t *testing.T) {
			token := e.token(rt.otherScope())
			rec := e.do(call{
				Method: rt.Method, Path: concretePath(t, rt.Pattern), Token: token,
				Body: "this is not json at all",
			})
			requireProblem(t, rec, http.StatusForbidden)
		})
	}
}

// malformedBodies are payloads no v1 endpoint may accept. Each must produce a
// 4xx problem — a 5xx here means an unvalidated value reached the database.
var malformedBodies = []struct {
	name, body string
}{
	{"truncated json", `{"calories":`},
	{"not an object", `[1,2,3]`},
	{"unknown field", `{"__definitely_not_a_field__":1}`},
	{"wrong field type", `{"name":12345}`},
	{"two json values", `{} {}`},
	{"bare string", `"hello"`},
}

// TestV1MalformedBodiesAreNeverA500 is the table that would have caught the
// open v1 bugs: every writable endpoint, every kind of bad payload, asserting
// only what the contract promises — a 4xx problem+json, never a 5xx.
func TestV1MalformedBodiesAreNeverA500(t *testing.T) {
	e := newV1Env(t)
	token := e.allScopesToken()

	for _, rt := range v1Routes(t) {
		if !rt.hasBody() {
			continue
		}
		for _, bad := range malformedBodies {
			t.Run(rt.String()+"/"+bad.name, func(t *testing.T) {
				rec := e.do(call{
					Method: rt.Method, Path: concretePath(t, rt.Pattern),
					Token: token, Body: bad.body,
				})

				if rec.Code >= 500 {
					t.Fatalf("status = %d for a malformed body; a client error must never surface as a server error (body: %s)",
						rec.Code, rec.Body.String())
				}
				if rec.Code < 400 {
					t.Fatalf("status = %d — the payload %s was accepted (body: %s)",
						rec.Code, bad.body, rec.Body.String())
				}
				requireProblemShape(t, rec)
			})
		}
	}
}

// TestV1MalformedPathParametersAreNeverA500 does the same for the values that
// arrive in the URL. An id of "not-an-int" or a date of "2026-02-31" must be
// rejected by the handler, not by Postgres.
func TestV1MalformedPathParametersAreNeverA500(t *testing.T) {
	e := newV1Env(t)
	token := e.allScopesToken()

	bad := map[string][]string{
		"{id}":   {"not-an-int", "0", "-1", "9999999999999999999999"},
		"{date}": {"not-a-date", "2026-02-31", "2026-13-01", "2026-1-1", "0001-01-01"},
	}

	for _, rt := range v1Routes(t) {
		for param, values := range bad {
			if !containsParam(rt.Pattern, param) {
				continue
			}
			for _, v := range values {
				t.Run(rt.String()+"/"+param+"="+v, func(t *testing.T) {
					path := concretePath(t, replaceParam(rt.Pattern, param, v))
					rec := e.do(call{
						Method: rt.Method, Path: path, Token: token,
						Body: bodyFor(rt),
					})
					if rec.Code >= 500 {
						t.Fatalf("status = %d for %s=%q; the handler must reject it before it reaches SQL (body: %s)",
							rec.Code, param, v, rec.Body.String())
					}
					if rec.Code < 400 {
						t.Fatalf("status = %d — %s=%q was accepted (body: %s)",
							rec.Code, param, v, rec.Body.String())
					}
					requireProblemShape(t, rec)
				})
			}
		}
	}
}

// TestV1MalformedQueryParametersAreNeverA500 covers the query-string
// validators: limit, cursor, the date filters, and ?user=.
func TestV1MalformedQueryParametersAreNeverA500(t *testing.T) {
	e := newV1Env(t)
	token := e.allScopesToken()

	queries := []string{
		"?limit=abc",
		"?limit=0",
		"?limit=-5",
		"?limit=99999999999999999999",
		"?cursor=not-base64!!",
		"?cursor=" + "Zm9vYmFy", // decodes, but is not date,id
		"?from=nope",
		"?to=2026-02-31",
		"?from=2026-08-05&to=2026-08-01",
		"?date=2026-08-05&from=2026-08-01",
		"?user=abc",
		"?user=-1",
		"?user=99999999999999999999",
	}

	for _, rt := range v1Routes(t) {
		if rt.Method != http.MethodGet {
			continue
		}
		for _, q := range queries {
			t.Run(rt.String()+"/"+q, func(t *testing.T) {
				rec := e.get(concretePath(t, rt.Pattern)+q, token)
				if rec.Code >= 500 {
					t.Fatalf("status = %d for %s; a bad query parameter is the caller's error (body: %s)",
						rec.Code, q, rec.Body.String())
				}
				if rec.Code >= 400 {
					requireProblemShape(t, rec)
				}
			})
		}
	}
}

// TestV1ReadsSucceedForAFreshAccount is the smoke half of the table: with a
// full-scope token and an account holding no data at all, no read may 500.
// An empty account is the state every new integration starts in.
func TestV1ReadsSucceedForAFreshAccount(t *testing.T) {
	e := newV1Env(t)
	token := e.allScopesToken()

	for _, rt := range v1Routes(t) {
		if rt.Method != http.MethodGet {
			continue
		}
		t.Run(rt.String(), func(t *testing.T) {
			rec := e.get(concretePath(t, rt.Pattern), token)
			if rec.Code >= 500 {
				t.Fatalf("status = %d on an empty account (body: %s)", rec.Code, rec.Body.String())
			}
			if rec.Code >= 400 {
				requireProblemShape(t, rec)
			}
		})
	}
}

// TestV1UnknownPathsAndMethodsAreProblemJSON checks chi's own generated
// responses, including the authenticated case where the token is valid but the
// path is not.
func TestV1UnknownPathsAndMethodsAreProblemJSON(t *testing.T) {
	e := newV1Env(t)
	token := e.allScopesToken()

	cases := []struct {
		name   string
		call   call
		status int
	}{
		{"unknown path, anonymous", call{Method: http.MethodGet, Path: "/api/v1/nope"}, http.StatusNotFound},
		{"unknown path, authenticated", call{Method: http.MethodGet, Path: "/api/v1/nope", Token: token}, http.StatusNotFound},
		{"unknown nested path", call{Method: http.MethodGet, Path: "/api/v1/entries/1/nope", Token: token}, http.StatusNotFound},
		{"method not allowed", call{Method: http.MethodDelete, Path: "/api/v1/me", Token: token}, http.StatusMethodNotAllowed},
		{"method not allowed on a collection", call{Method: http.MethodPut, Path: "/api/v1/entries", Token: token}, http.StatusMethodNotAllowed},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requireProblem(t, e.do(c.call), c.status)
		})
	}
}

// TestV1CookieDoesNotAuthenticateAnyEndpoint extends invariant #1 from the one
// endpoint TestV1CookiesAreNotAccepted checks to the whole surface, with a
// session cookie that is real rather than made up in the sense that matters:
// the middleware must not even look at it.
func TestV1CookieDoesNotAuthenticateAnyEndpoint(t *testing.T) {
	e := newV1Env(t)

	for _, rt := range v1Routes(t) {
		t.Run(rt.String(), func(t *testing.T) {
			rec := e.do(call{
				Method: rt.Method, Path: concretePath(t, rt.Pattern),
				Headers: map[string]string{"Cookie": "schautrack.sid=whatever"},
			})
			requireProblem(t, rec, http.StatusUnauthorized)
		})
	}
}

// TestV1WriteScopeImpliesRead asserts the ScopeSatisfies rule end-to-end: a
// token holding only entries:write really can GET /entries. The unit test
// proves the predicate; this proves the middleware uses it.
func TestV1WriteScopeImpliesRead(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	rec := e.get("/api/v1/entries", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — entries:write must satisfy entries:read (body: %s)",
			rec.Code, rec.Body.String())
	}
}

// --- helpers --------------------------------------------------------------

func containsParam(pattern, param string) bool { return strings.Contains(pattern, param) }

func replaceParam(pattern, param, value string) string {
	return strings.Replace(pattern, param, value, 1)
}

// bodyFor supplies a minimally valid body so a path-parameter test fails on the
// parameter rather than on a missing payload.
func bodyFor(rt v1Route) string {
	if !rt.hasBody() {
		return ""
	}
	switch rt.Pattern {
	case "/weight/{date}":
		return `{"weight":82.4}`
	case "/notes/{date}":
		return `{"content":"hello"}`
	case "/todos/{id}/completions/{date}":
		return `{"completed":true}`
	case "/entries/{id}":
		return `{"calories":100}`
	case "/saved-foods/{id}":
		return `{"name":"x"}`
	case "/saved-foods/{id}/track":
		return `{"quantity":1}`
	}
	return `{}`
}
