package handler

import (
	"fmt"
	"net/http"
	"testing"

	"schautrack/internal/service"
)

// A NUL byte in a text field is a 500. See #378.
//
// nulEscape below is the six characters backslash-u-zero-zero-zero-zero: a
// perfectly legal JSON escape that decodes to a Go string containing 0x00.
// Postgres TEXT cannot store that byte, so the INSERT fails with SQLSTATE 22021
// and dbFail turns a client mistake into an internal-error problem.
//
// These tests assert the CURRENT behaviour deliberately. Writing them the right
// way round would mean committing a red suite; writing them loosely ("4xx or
// 5xx, whatever") would mean the fix lands with nothing noticing. Pinned to 500
// with a pointer to #378, they fail the moment someone fixes it — which is the
// signal the fixer needs to invert them.
//
// TODO(#378): when a NUL is rejected before it reaches SQL, change every
// expected status below to the 4xx it should have been all along and rename
// this file to say what it now guards.
const nulEscape = `\u0000`

func TestV1NulByteInATextFieldIsAn500(t *testing.T) {
	e := newV1Env(t)
	token := e.allScopesToken()

	// Seed the resources the PATCH cases address.
	entry := e.createEntry(token, `{"calories":100,"name":"ok"}`)

	foodRec := e.post("/api/v1/saved-foods", token, `{"name":"ok food","calories":10}`)
	if foodRec.Code != http.StatusCreated {
		t.Fatalf("seeding a saved food: status = %d (body: %s)", foodRec.Code, foodRec.Body.String())
	}
	var food v1SavedFood
	decodeJSON(t, foodRec, &food)

	todoRec := e.post("/api/v1/todos", token, `{"name":"ok todo","schedule":{"type":"daily"}}`)
	if todoRec.Code != http.StatusCreated {
		t.Fatalf("seeding a todo: status = %d (body: %s)", todoRec.Code, todoRec.Body.String())
	}
	var todo v1Todo
	decodeJSON(t, todoRec, &todo)

	cases := []struct{ name, method, path, body string }{
		{"POST /entries name", http.MethodPost, "/api/v1/entries",
			`{"calories":100,"name":"a` + nulEscape + `b"}`},
		{"PATCH /entries/{id} name", http.MethodPatch, fmt.Sprintf("/api/v1/entries/%d", entry.ID),
			`{"name":"a` + nulEscape + `b"}`},
		{"POST /saved-foods name", http.MethodPost, "/api/v1/saved-foods",
			`{"name":"a` + nulEscape + `b","calories":10}`},
		{"POST /saved-foods emoji", http.MethodPost, "/api/v1/saved-foods",
			`{"name":"emoji case","emoji":"a` + nulEscape + `b"}`},
		{"PATCH /saved-foods/{id} name", http.MethodPatch, fmt.Sprintf("/api/v1/saved-foods/%d", food.ID),
			`{"name":"a` + nulEscape + `b"}`},
		{"PATCH /saved-foods/{id} emoji", http.MethodPatch, fmt.Sprintf("/api/v1/saved-foods/%d", food.ID),
			`{"emoji":"a` + nulEscape + `b"}`},
		{"POST /todos name", http.MethodPost, "/api/v1/todos",
			`{"name":"a` + nulEscape + `b","schedule":{"type":"daily"}}`},
		{"PATCH /todos/{id} name", http.MethodPatch, fmt.Sprintf("/api/v1/todos/%d", todo.ID),
			`{"name":"a` + nulEscape + `b"}`},
		{"PUT /notes/{date} content", http.MethodPut, "/api/v1/notes/2026-08-05",
			`{"content":"a` + nulEscape + `b"}`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := e.do(call{Method: c.method, Path: c.path, Token: token, Body: c.body})

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d — if this is now a 4xx, #378 is fixed: invert every assertion "+
					"in this file and rename it (body: %s)", rec.Code, rec.Body.String())
			}
			// Whatever the status, the contract's error format still holds.
			requireProblemShape(t, rec)
		})
	}
}

// TestV1ValidatedFieldsRejectNulProperly is the other half of #378, and the
// reason the fix is worth making: the fields that go through a parser or a
// closed set already answer 422. The string columns are the exception, not the
// rule.
func TestV1ValidatedFieldsRejectNulProperly(t *testing.T) {
	e := newV1Env(t)
	token := e.allScopesToken()

	cases := []struct{ name, method, path, body string }{
		{"timezone", http.MethodPatch, "/api/v1/me", `{"timezone":"UTC` + nulEscape + `"}`},
		{"language", http.MethodPatch, "/api/v1/me", `{"language":"e` + nulEscape + `n"}`},
		{"weight_unit", http.MethodPatch, "/api/v1/me", `{"weight_unit":"kg` + nulEscape + `"}`},
		{"entry date", http.MethodPost, "/api/v1/entries", `{"calories":1,"date":"` + nulEscape + `"}`},
		{"todo time_of_day", http.MethodPost, "/api/v1/todos",
			`{"name":"tod","schedule":{"type":"daily"},"time_of_day":"08:0` + nulEscape + `"}`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := e.do(call{Method: c.method, Path: c.path, Token: token, Body: c.body})
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422 (body: %s)", rec.Code, rec.Body.String())
			}
			requireProblemShape(t, rec)
		})
	}
}

// TestV1NulByteInAQueryParameterIsRejected: the query-string validators do get
// this right, so the parsing layer is not the problem — the missing check is on
// the free-text body fields.
func TestV1NulByteInAQueryParameterIsRejected(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesRead, service.ScopeLinksRead)

	for _, q := range []string{"?date=2026-08-05%00", "?user=1%00", "?limit=5%00", "?cursor=abc%00"} {
		t.Run(q, func(t *testing.T) {
			rec := e.get("/api/v1/entries"+q, token)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
			requireProblemShape(t, rec)
		})
	}
}
