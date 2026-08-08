package handler

import (
	"fmt"
	"net/http"
	"testing"

	"schautrack/internal/service"
)

// A NUL byte in a text field is a 400. See #378, now fixed.
//
// nulEscape below is the six characters backslash-u-zero-zero-zero-zero: a
// perfectly legal JSON escape that decodes to a Go string containing 0x00.
// Postgres TEXT cannot store that byte, so the INSERT used to fail with
// SQLSTATE 22021 and dbFail turned a client mistake into a 500.
//
// These assertions were pinned to 500 on purpose while the bug stood, with a
// TODO asking whoever fixed it to invert them. That is what happened: decodeV1
// now refuses the escape on the raw body before anything is decoded, so every
// v1 endpoint answers 400 rather than ten handlers each learning the lesson
// separately.
const nulEscape = `\u0000`

func TestV1NulByteInATextFieldIsRejected(t *testing.T) {
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

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 — a NUL is the caller's mistake, never a server "+
					"failure (body: %s)", rec.Code, rec.Body.String())
			}
			// Whatever the status, the contract's error format still holds.
			requireProblemShape(t, rec)
		})
	}
}

// TestV1ValidatedFieldsRejectNul covers the fields that have their own parser
// or closed set. They used to answer 422 — the value was well-formed JSON but
// not a legal timezone/language/date — while the free-text columns 500d.
//
// Both are 400 now, because the check that fires first is about the ENCODING
// rather than the value: a NUL cannot be stored in any text column, so which
// field it landed in does not change the answer. Uniform is the right trade
// here; the alternative is a rule whose status depends on whether the field
// happens to have a validator, which no client could predict.
func TestV1ValidatedFieldsRejectNul(t *testing.T) {
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
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
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
