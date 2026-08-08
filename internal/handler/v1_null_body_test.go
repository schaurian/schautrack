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

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/apierr"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
)

// Regression tests for #347, at the level where the bug actually cost data.
//
// The unit-level pin lives in v1_common_test.go ("bare JSON null"), but a
// parser test cannot show that the parser was destroying rows. These drive the
// two v1 handlers where a zero-valued input is read as a *destructive
// instruction* — PUT /notes/{date} and PUT /todos/{id}/completions/{date} —
// against a real database, and assert the row is still there afterwards.
//
// Both also assert the intended delete still works, so a fix that turns
// decodeV1 into a blanket rejection of empty-ish bodies fails here rather than
// shipping a second regression.
//
// Skipped unless TEST_DATABASE_URL is set, matching internal/database's
// integration tests. CI sets it.

// v1TestDB opens the integration pool and runs the migrations, or skips.
func v1TestDB(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	// database.NewPool, not a bare pgxpool.New: the production pool registers a
	// codec that scans DATE columns straight into string (see
	// database.dateStringCodec), and several v1 handlers scan into a string
	// date field. A plain pool makes those handlers fail with a scan error that
	// cannot happen in the running app — a test harness that manufactures its
	// own bugs is worse than no test.
	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return ctx, pool
}

// v1TestUser seeds a user with notes enabled and removes it afterwards.
func v1TestUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) *model.User {
	t.Helper()
	cleanup := func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, email) }
	cleanup()
	t.Cleanup(cleanup)

	var id int
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, email_verified, notes_enabled, timezone)
		 VALUES ($1, 'x', true, true, 'UTC') RETURNING id`, email).Scan(&id); err != nil {
		t.Fatalf("seeding the user failed: %v", err)
	}
	tz := "UTC"
	return &model.User{ID: id, Email: email, Timezone: &tz}
}

// v1PutJSON drives a v1 handler with a raw body and the given path params.
func v1PutJSON(ctx context.Context, h http.HandlerFunc, u *model.User, path, body string,
	params map[string]string) *httptest.ResponseRecorder {
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	c := context.WithValue(middleware.WithTestUser(ctx, u), chi.RouteCtxKey, rctx)

	r := httptest.NewRequest(http.MethodPut, path, strings.NewReader(body)).WithContext(c)
	rec := httptest.NewRecorder()
	h(rec, r)
	return rec
}

// assertProblem decodes a problem+json body and checks the status and detail.
func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantDetail string) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d (body %s)", rec.Code, wantStatus, rec.Body.String())
	}
	// Invariant #3: every v1 error is problem+json, including this new one.
	if ct := rec.Header().Get("Content-Type"); ct != apierr.ContentType {
		t.Errorf("Content-Type = %q, want %q", ct, apierr.ContentType)
	}
	var p apierr.Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("response is not JSON: %v (body %s)", err, rec.Body.String())
	}
	if p.Detail != wantDetail {
		t.Errorf("detail = %q, want %q", p.Detail, wantDetail)
	}
	if p.Status != wantStatus {
		t.Errorf("problem.status = %d, want %d", p.Status, wantStatus)
	}
}

// TestPutNoteV1RejectsNullBody is the data-loss case from #347.
//
// A client wrapper that serialises "no payload" as `json.dumps(None)` sends the
// four bytes `null`. Before the fix decodeV1 accepted them, PutNoteV1 saw
// Content == "" and ran DELETE FROM daily_notes, and the caller got a 200 —
// the note was gone and nothing in the exchange said so.
func TestPutNoteV1RejectsNullBody(t *testing.T) {
	ctx, pool := v1TestDB(t)
	user := v1TestUser(t, ctx, pool, "v1-null-note@handler.test")
	h := &V1Handler{Pool: pool}

	const date = "2026-08-08"
	const content = "buy oat milk"
	seed := func() {
		if _, err := pool.Exec(ctx,
			`INSERT INTO daily_notes (user_id, note_date, content) VALUES ($1, $2, $3)
			 ON CONFLICT (user_id, note_date) DO UPDATE SET content = EXCLUDED.content`,
			user.ID, date, content); err != nil {
			t.Fatalf("seeding the note failed: %v", err)
		}
	}
	read := func() (string, bool) {
		var got string
		err := pool.QueryRow(ctx,
			`SELECT content FROM daily_notes WHERE user_id = $1 AND note_date = $2`,
			user.ID, date).Scan(&got)
		if err != nil {
			return "", false
		}
		return got, true
	}
	put := func(body string) *httptest.ResponseRecorder {
		return v1PutJSON(ctx, h.PutNoteV1, user, "/api/v1/notes/"+date, body,
			map[string]string{"date": date})
	}

	t.Run("null body leaves the note intact", func(t *testing.T) {
		seed()
		rec := put(`null`)
		assertProblem(t, rec, http.StatusBadRequest, "The request body must be a JSON object.")

		got, ok := read()
		if !ok {
			t.Fatal("a body of `null` deleted the note — #347 has regressed")
		}
		if got != content {
			t.Errorf("content = %q, want %q unchanged", got, content)
		}
	})

	t.Run("null body with whitespace is still rejected", func(t *testing.T) {
		seed()
		rec := put("  \n null \n ")
		assertProblem(t, rec, http.StatusBadRequest, "The request body must be a JSON object.")
		if _, ok := read(); !ok {
			t.Fatal("a whitespace-padded `null` deleted the note")
		}
	})

	t.Run("a real note still saves", func(t *testing.T) {
		seed()
		rec := put(`{"content":"eggs"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		got, ok := read()
		if !ok || got != "eggs" {
			t.Errorf("note = %q, %v; want %q saved", got, ok, "eggs")
		}
	})

	t.Run("an explicit empty content still deletes", func(t *testing.T) {
		// The intended delete path. A fix that made decodeV1 refuse anything
		// yielding a zero-valued struct would break this.
		seed()
		rec := put(`{"content":""}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		if got, ok := read(); ok {
			t.Errorf("note still present with content %q, want it deleted", got)
		}
	})

	t.Run("an empty object still deletes", func(t *testing.T) {
		// The deliberate line from #347, pinned here as well as in
		// TestDecodeV1EmptyObjectIsNotRejected: `{}` is an object and keeps its
		// pre-fix meaning on this whole-content-replace PUT. Only `null` — not
		// an object, and carrying no statement about the note — changed. If
		// this endpoint should instead require the `content` key, that is a
		// v1NoteInput change and its own reviewed decision.
		seed()
		rec := put(`{}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		if got, ok := read(); ok {
			t.Errorf("note still present with content %q; `{}` behaviour changed as a side effect", got)
		}
	})
}

// TestSetTodoCompletionV1RejectsNullBody is the second destructive endpoint
// #347 reaches: a zero-valued v1CompletionInput is Completed:false, which is
// "un-complete this todo" — it deletes the completion row and breaks the
// streak the user was keeping.
func TestSetTodoCompletionV1RejectsNullBody(t *testing.T) {
	ctx, pool := v1TestDB(t)
	user := v1TestUser(t, ctx, pool, "v1-null-todo@handler.test")
	h := &V1Handler{Pool: pool}

	const date = "2026-08-08"
	var todoID int
	if err := pool.QueryRow(ctx,
		`INSERT INTO todos (user_id, name, schedule) VALUES ($1, 'stretch', '{"type":"daily"}')
		 RETURNING id`, user.ID).Scan(&todoID); err != nil {
		t.Fatalf("seeding the todo failed: %v", err)
	}

	seed := func() {
		if _, err := pool.Exec(ctx,
			`INSERT INTO todo_completions (todo_id, user_id, completion_date) VALUES ($1, $2, $3)
			 ON CONFLICT DO NOTHING`, todoID, user.ID, date); err != nil {
			t.Fatalf("seeding the completion failed: %v", err)
		}
	}
	completed := func() bool {
		var ok bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM todo_completions
			  WHERE todo_id = $1 AND user_id = $2 AND completion_date = $3)`,
			todoID, user.ID, date).Scan(&ok); err != nil {
			t.Fatalf("reading the completion back failed: %v", err)
		}
		return ok
	}
	put := func(body string) *httptest.ResponseRecorder {
		return v1PutJSON(ctx, h.SetTodoCompletionV1, user,
			"/api/v1/todos/x/completions/"+date, body,
			map[string]string{"id": strconv.Itoa(todoID), "date": date})
	}

	t.Run("null body leaves the completion intact", func(t *testing.T) {
		seed()
		rec := put(`null`)
		assertProblem(t, rec, http.StatusBadRequest, "The request body must be a JSON object.")
		if !completed() {
			t.Fatal("a body of `null` cleared the completion — #347 has regressed")
		}
	})

	t.Run("an explicit false still un-completes", func(t *testing.T) {
		seed()
		rec := put(`{"completed":false}`)
		if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 2xx (body %s)", rec.Code, rec.Body.String())
		}
		if completed() {
			t.Error("completion still present after an explicit completed:false")
		}
	})

	t.Run("an explicit true still completes", func(t *testing.T) {
		rec := put(`{"completed":true}`)
		if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 2xx (body %s)", rec.Code, rec.Body.String())
		}
		if !completed() {
			t.Error("completion missing after an explicit completed:true")
		}
	})
}
