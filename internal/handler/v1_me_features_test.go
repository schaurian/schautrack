package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"schautrack/internal/database"
	"schautrack/internal/model"
	"schautrack/internal/openapi"
	"schautrack/internal/service"
)

// The features block on GET /api/v1/me (#344).
//
// Two things have to hold and they fail in different ways:
//
//  1. Each flag comes from its own column. A copy-paste swap between
//     body_fat_enabled and notes_enabled produces a response that is valid,
//     plausible, and wrong — no schema check would catch it, so every flag is
//     asserted in isolation below.
//  2. macros is derived, not stored. users.macros_enabled is a JSONB map of
//     per-macro toggles plus auto_calc_calories; the rollup and the auto-calc
//     flag are independent, and auto_calc is the one with an observable API
//     consequence (a 422 on PATCH /entries/{id}).

// buildMeFeatures runs buildMe over a user and returns just the features block.
func buildMeFeatures(t *testing.T, u *model.User) v1Features {
	t.Helper()
	h := &V1Handler{BuildVersion: "test"}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	return h.buildMe(req, u).Features
}

func TestBuildMeFeatures(t *testing.T) {
	cases := []struct {
		name string
		user model.User
		want v1Features
	}{
		{
			name: "a fresh account has everything off",
			user: model.User{MacrosEnabled: json.RawMessage(`{}`)},
			want: v1Features{},
		},
		{
			// macros_enabled is nullable and predates its own default, so an
			// old row can hold SQL NULL. ParseMacroUser must not panic and the
			// answer must be "off", not "unknown".
			name: "a null macros_enabled reads as off",
			user: model.User{MacrosEnabled: nil},
			want: v1Features{},
		},
		{
			name: "body_fat comes from body_fat_enabled alone",
			user: model.User{BodyFatEnabled: true, MacrosEnabled: json.RawMessage(`{}`)},
			want: v1Features{BodyFat: true},
		},
		{
			name: "todos comes from todos_enabled alone",
			user: model.User{TodosEnabled: true, MacrosEnabled: json.RawMessage(`{}`)},
			want: v1Features{Todos: true},
		},
		{
			name: "notes comes from notes_enabled alone",
			user: model.User{NotesEnabled: true, MacrosEnabled: json.RawMessage(`{}`)},
			want: v1Features{Notes: true},
		},
		{
			name: "one enabled macro is enough for the rollup",
			user: model.User{MacrosEnabled: json.RawMessage(`{"protein":true}`)},
			want: v1Features{Macros: true},
		},
		{
			// "calories" lives in the same JSONB object but is not a macro —
			// counting it would report macros:true for an account that shows
			// no macro at all.
			name: "calories alone is not a macro",
			user: model.User{MacrosEnabled: json.RawMessage(`{"calories":true}`)},
			want: v1Features{},
		},
		{
			name: "explicitly disabled macros stay off",
			user: model.User{MacrosEnabled: json.RawMessage(
				`{"protein":false,"carbs":false,"fat":false,"fiber":false,"sugar":false}`)},
			want: v1Features{},
		},
		{
			name: "auto_calc_calories is reported independently of the rollup",
			user: model.User{MacrosEnabled: json.RawMessage(`{"auto_calc_calories":true}`)},
			want: v1Features{AutoCalcCalories: true},
		},
		{
			// The state migration 373 creates: protein+carbs+fat on, so
			// auto-calc was switched on with them.
			name: "the full macro account",
			user: model.User{
				TodosEnabled: true, NotesEnabled: true, BodyFatEnabled: true,
				MacrosEnabled: json.RawMessage(
					`{"calories":true,"protein":true,"carbs":true,"fat":true,"fiber":true,"sugar":true,"auto_calc_calories":true}`),
			},
			want: v1Features{BodyFat: true, Todos: true, Notes: true, Macros: true, AutoCalcCalories: true},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := buildMeFeatures(t, &c.user); got != c.want {
				t.Errorf("features = %+v, want %+v", got, c.want)
			}
		})
	}
}

// The 422 on PATCH /entries/{id} and the auto_calc_calories flag must be driven
// by the same predicate. If they ever diverge, /me would advertise that
// calories are writable on an account that rejects them — the exact "you can
// only find out by getting an error" problem #344 is about.
func TestAutoCalcFlagMatchesTheEntryHandlersPredicate(t *testing.T) {
	for _, raw := range []string{
		`{}`,
		`{"auto_calc_calories":true}`,
		`{"auto_calc_calories":false}`,
		`{"protein":true,"carbs":true,"fat":true,"auto_calc_calories":true}`,
	} {
		u := model.User{MacrosEnabled: json.RawMessage(raw)}
		mu := service.ParseMacroUser(u.MacrosEnabled, u.MacroGoals, u.DailyGoal, u.GoalThreshold)
		want := service.IsAutoCalcCalories(mu)
		if got := buildMeFeatures(t, &u).AutoCalcCalories; got != want {
			t.Errorf("macros_enabled=%s: /me reports auto_calc_calories=%v but the entry handlers use %v",
				raw, got, want)
		}
	}
}

// TestMeFeaturesRoundTripFromDatabase drives the real router — RequireAPIToken,
// middleware.GetUserByID, the handler, the JSON encoder — against a real
// Postgres, so it covers the one thing the unit test above cannot: that
// GetUserByID actually SELECTs these columns and lands them on the right struct
// fields. A column dropped from that query would leave every in-process test
// green and ship a /me that reports false for an enabled feature.
//
// Skipped unless TEST_DATABASE_URL is set, matching the other integration tests
// in this package. CI sets it (#325).
func TestMeFeaturesRoundTripFromDatabase(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	h := &V1Handler{Pool: pool, BuildVersion: "test"}
	router := h.MountAPIV1(pool)
	doc := openapi.Build("", "")

	cases := []struct {
		name          string
		email         string
		todos         bool
		notes         bool
		bodyFat       bool
		macrosEnabled string
		want          v1Features
	}{
		{
			name: "every feature on", email: "me-features-on@handler.test",
			todos: true, notes: true, bodyFat: true,
			macrosEnabled: `{"calories":true,"protein":true,"carbs":true,"fat":true,"fiber":true,"sugar":true,"auto_calc_calories":true}`,
			want:          v1Features{BodyFat: true, Todos: true, Notes: true, Macros: true, AutoCalcCalories: true},
		},
		{
			name: "every feature off", email: "me-features-off@handler.test",
			macrosEnabled: `{}`,
			want:          v1Features{},
		},
		{
			// Half on, so a handler that returned a constant or read one column
			// for several flags cannot pass both this and the cases above.
			name: "notes on, todos off", email: "me-features-mixed@handler.test",
			notes: true, macrosEnabled: `{"protein":true,"auto_calc_calories":false}`,
			want: v1Features{Notes: true, Macros: true},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cleanup := func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, c.email) }
			cleanup()
			t.Cleanup(cleanup)

			var userID int
			if err := pool.QueryRow(ctx, `
				INSERT INTO users (email, password_hash, email_verified, timezone,
					todos_enabled, notes_enabled, body_fat_enabled, macros_enabled)
				VALUES ($1, 'x', true, 'Europe/Berlin', $2, $3, $4, $5::jsonb) RETURNING id`,
				c.email, c.todos, c.notes, c.bodyFat, c.macrosEnabled).Scan(&userID); err != nil {
				t.Fatalf("seeding the user failed: %v", err)
			}

			_, raw, err := service.CreateAPIToken(ctx, pool, userID, "features test",
				[]string{service.ScopeSettingsRead}, nil)
			if err != nil {
				t.Fatalf("minting a token failed: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			req.Header.Set("Authorization", "Bearer "+raw)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req.WithContext(ctx))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}

			// The response still has to satisfy the published document, with
			// the features object in it.
			if err := doc.ValidateJSON("Me", rec.Body.Bytes()); err != nil {
				t.Errorf("%v\n\nresponse: %s", err, rec.Body.String())
			}

			var got struct {
				Features v1Features `json:"features"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("response is not valid JSON: %v", err)
			}
			if got.Features != c.want {
				t.Errorf("features = %+v, want %+v\n\nresponse: %s", got.Features, c.want, rec.Body.String())
			}

			// Compare against what the database holds right now rather than
			// against the literals above: this is the round trip the issue
			// asks for, and it fails if the SELECT ever stops reading a column.
			var dbTodos, dbNotes, dbBodyFat bool
			if err := pool.QueryRow(ctx,
				`SELECT todos_enabled, notes_enabled, body_fat_enabled FROM users WHERE id = $1`,
				userID).Scan(&dbTodos, &dbNotes, &dbBodyFat); err != nil {
				t.Fatalf("reading the columns back failed: %v", err)
			}
			if got.Features.Todos != dbTodos {
				t.Errorf("features.todos = %v but users.todos_enabled = %v", got.Features.Todos, dbTodos)
			}
			if got.Features.Notes != dbNotes {
				t.Errorf("features.notes = %v but users.notes_enabled = %v", got.Features.Notes, dbNotes)
			}
			if got.Features.BodyFat != dbBodyFat {
				t.Errorf("features.body_fat = %v but users.body_fat_enabled = %v", got.Features.BodyFat, dbBodyFat)
			}
		})
	}
}
