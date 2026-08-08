package handler

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"schautrack/internal/service"
)

// Behaviour of the remaining resources: weight, notes, todos, saved foods and
// /me. Between them these hold the majority of the unexecuted apierr.* branches
// the issue counts (v1_foods.go 13, v1_capabilities.go 11, v1_weight.go 4,
// v1_todos.go 3, v1_misc.go 2).

// --- Weight ---------------------------------------------------------------

// TestV1WeightPutIsAnUpsert covers the 201-then-200 distinction PutWeightV1
// documents, which is how a scale integration tells "first reading today" from
// "corrected reading".
func TestV1WeightPutIsAnUpsert(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeWeightWrite)

	first := e.do(call{Method: http.MethodPut, Path: "/api/v1/weight/2026-08-05",
		Token: token, Body: `{"weight":82.4}`})
	if first.Code != http.StatusCreated {
		t.Fatalf("first PUT: status = %d, want 201 (body: %s)", first.Code, first.Body.String())
	}
	if first.Header().Get("Location") == "" {
		t.Error("no Location header on the 201")
	}
	requireSchema(t, first, "Weight")

	second := e.do(call{Method: http.MethodPut, Path: "/api/v1/weight/2026-08-05",
		Token: token, Body: `{"weight":82.1}`})
	if second.Code != http.StatusOK {
		t.Fatalf("replacing PUT: status = %d, want 200 (body: %s)", second.Code, second.Body.String())
	}

	var w v1Weight
	decodeJSON(t, second, &w)
	if w.Weight != 82.1 {
		t.Errorf("weight = %v, want 82.1", w.Weight)
	}

	// Exactly one row: the unique index is what makes PUT idempotent.
	var n int
	if err := e.Pool.QueryRow(e.Ctx,
		`SELECT COUNT(*)::int FROM weight_entries WHERE user_id = $1`, e.UserID).Scan(&n); err != nil {
		t.Fatalf("counting weight rows: %v", err)
	}
	if n != 1 {
		t.Errorf("%d weight rows for one date, want 1", n)
	}
}

// TestV1WeightRejectsUnusableValues covers ParseWeight's bounds reached through
// the API, including the values a CHECK constraint would otherwise turn into a
// 500.
func TestV1WeightRejectsUnusableValues(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeWeightWrite)

	for _, body := range []string{
		`{"weight":0}`,
		`{"weight":-5}`,
		`{"weight":1501}`,
		`{"weight":1e30}`,
		`{}`, // absent weight decodes to the zero value, which is not usable
	} {
		t.Run(body, func(t *testing.T) {
			rec := e.do(call{Method: http.MethodPut, Path: "/api/v1/weight/2026-08-05",
				Token: token, Body: body})

			p := requireProblem(t, rec, http.StatusUnprocessableEntity)
			if len(p.InvalidParams) == 0 || p.InvalidParams[0].Name != "weight" {
				t.Errorf("invalid_params = %+v, want it to name weight", p.InvalidParams)
			}
		})
	}
}

// TestV1WeightMissingAndDeleted covers the two 404 branches.
func TestV1WeightMissingAndDeleted(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeWeightWrite)

	requireProblem(t, e.get("/api/v1/weight/2026-08-05", token), http.StatusNotFound)
	requireProblem(t, e.do(call{Method: http.MethodDelete, Path: "/api/v1/weight/2026-08-05", Token: token}),
		http.StatusNotFound)

	e.do(call{Method: http.MethodPut, Path: "/api/v1/weight/2026-08-05", Token: token, Body: `{"weight":82.4}`})

	if rec := e.get("/api/v1/weight/2026-08-05", token); rec.Code != http.StatusOK {
		t.Fatalf("GET after PUT: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	if rec := e.do(call{Method: http.MethodDelete, Path: "/api/v1/weight/2026-08-05", Token: token}); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE: status = %d, want 204 (body: %s)", rec.Code, rec.Body.String())
	}
	requireProblem(t, e.get("/api/v1/weight/2026-08-05", token), http.StatusNotFound)
}

// TestV1WeightPaginatesAcrossDates: weight is the collection that grows a row
// per day forever, so its cursor has to work.
func TestV1WeightPaginatesAcrossDates(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeWeightWrite)

	dates := []string{"2026-08-01", "2026-08-02", "2026-08-03", "2026-08-04"}
	for i, d := range dates {
		rec := e.do(call{Method: http.MethodPut, Path: "/api/v1/weight/" + d,
			Token: token, Body: fmt.Sprintf(`{"weight":%d.5}`, 80+i)})
		if rec.Code != http.StatusCreated {
			t.Fatalf("seeding %s: status = %d (body: %s)", d, rec.Code, rec.Body.String())
		}
	}

	var got []string
	path := "/api/v1/weight?limit=2"
	for page := 1; page <= 5; page++ {
		rec := e.get(path, token)
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d: status = %d (body: %s)", page, rec.Code, rec.Body.String())
		}
		requireSchema(t, rec, "WeightList")

		var body v1List[v1Weight]
		decodeJSON(t, rec, &body)
		for _, w := range body.Data {
			got = append(got, w.Date)
		}
		if body.HasMore == nil || !*body.HasMore {
			break
		}
		if body.NextCursor == nil {
			t.Fatalf("page %d says has_more but has no next_cursor", page)
		}
		path = "/api/v1/weight?limit=2&cursor=" + *body.NextCursor
	}

	want := []string{"2026-08-04", "2026-08-03", "2026-08-02", "2026-08-01"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("paged dates = %v, want %v", got, want)
	}
}

// --- Notes ----------------------------------------------------------------

// TestV1NoteRoundTrip covers the "no note is 200 with empty content, not 404"
// decision and the "writing an empty string deletes" one.
func TestV1NoteRoundTrip(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeNotesWrite)

	rec := e.get("/api/v1/notes/2026-08-05", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("a day with no note: status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	requireSchema(t, rec, "Note")
	var empty v1Note
	decodeJSON(t, rec, &empty)
	if empty.Content != "" || empty.UpdatedAt != nil {
		t.Errorf("empty day returned %+v", empty)
	}

	put := e.do(call{Method: http.MethodPut, Path: "/api/v1/notes/2026-08-05",
		Token: token, Body: `{"content":"Felt good."}`})
	if put.Code != http.StatusOK {
		t.Fatalf("PUT: status = %d (body: %s)", put.Code, put.Body.String())
	}
	requireSchema(t, put, "Note")

	var saved v1Note
	decodeJSON(t, e.get("/api/v1/notes/2026-08-05", token), &saved)
	if saved.Content != "Felt good." {
		t.Errorf("content = %q after a write", saved.Content)
	}

	// Writing empty deletes.
	e.do(call{Method: http.MethodPut, Path: "/api/v1/notes/2026-08-05", Token: token, Body: `{"content":"   "}`})
	var cleared v1Note
	decodeJSON(t, e.get("/api/v1/notes/2026-08-05", token), &cleared)
	if cleared.Content != "" {
		t.Errorf("content = %q after writing whitespace, want it cleared", cleared.Content)
	}
}

// TestV1NoteTooLong covers the maxNoteLen branch.
func TestV1NoteTooLong(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeNotesWrite)

	rec := e.do(call{Method: http.MethodPut, Path: "/api/v1/notes/2026-08-05",
		Token: token, Body: fmt.Sprintf(`{"content":%q}`, strings.Repeat("x", maxNoteLen+1))})

	p := requireProblem(t, rec, http.StatusUnprocessableEntity)
	if len(p.InvalidParams) == 0 || p.InvalidParams[0].Name != "content" {
		t.Errorf("invalid_params = %+v, want it to name content", p.InvalidParams)
	}
}

// TestV1NotesDisabledIs409 covers requireNotesEnabled: the endpoint exists and
// the token may use it, the account simply has the feature off — which is a
// state the caller can fix, so it must be said rather than 404'd.
func TestV1NotesDisabledIs409(t *testing.T) {
	e := newV1Env(t)
	if _, err := e.Pool.Exec(e.Ctx, `UPDATE users SET notes_enabled = FALSE WHERE id = $1`, e.UserID); err != nil {
		t.Fatalf("disabling notes: %v", err)
	}
	token := e.token(service.ScopeNotesWrite)

	requireProblem(t, e.get("/api/v1/notes/2026-08-05", token), http.StatusConflict)
	requireProblem(t, e.do(call{Method: http.MethodPut, Path: "/api/v1/notes/2026-08-05",
		Token: token, Body: `{"content":"hi"}`}), http.StatusConflict)
}

// --- Todos ----------------------------------------------------------------

// TestV1TodoValidation covers CreateTodoV1's rejection branches.
func TestV1TodoValidation(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeTodosWrite)

	cases := []struct {
		name, body, param string
	}{
		{"no name", `{"schedule":{"type":"daily"}}`, "name"},
		{"blank name", `{"name":"   ","schedule":{"type":"daily"}}`, "name"},
		{"no schedule", `{"name":"Walk"}`, "schedule"},
		{"unknown schedule type", `{"name":"Walk","schedule":{"type":"hourly"}}`, "schedule"},
		{"weekdays with no days", `{"name":"Walk","schedule":{"type":"weekdays","days":[]}}`, "schedule"},
		{"weekdays out of range", `{"name":"Walk","schedule":{"type":"weekdays","days":[0,9]}}`, "schedule"},
		{"bad time of day", `{"name":"Walk","schedule":{"type":"daily"},"time_of_day":"25:99"}`, "time_of_day"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := e.post("/api/v1/todos", token, c.body)

			p := requireProblem(t, rec, http.StatusUnprocessableEntity)
			if len(p.InvalidParams) == 0 || p.InvalidParams[0].Name != c.param {
				t.Errorf("invalid_params = %+v, want it to name %s", p.InvalidParams, c.param)
			}
		})
	}
}

// TestV1TodoLifecycle covers create, the day view, completion (twice, to prove
// PUT really is idempotent), un-completion, and the archive-on-delete.
func TestV1TodoLifecycle(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeTodosWrite)

	rec := e.post("/api/v1/todos", token, `{"name":"Walk the dog","schedule":{"type":"daily"},"time_of_day":"08:00"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /todos: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	requireSchema(t, rec, "Todo")
	var todo v1Todo
	decodeJSON(t, rec, &todo)

	day := e.get("/api/v1/todos/day/2026-08-05", token)
	if day.Code != http.StatusOK {
		t.Fatalf("GET /todos/day: status = %d (body: %s)", day.Code, day.Body.String())
	}
	requireSchema(t, day, "TodoDayList")

	completion := fmt.Sprintf("/api/v1/todos/%d/completions/2026-08-05", todo.ID)
	for i := 0; i < 2; i++ {
		rec := e.do(call{Method: http.MethodPut, Path: completion, Token: token, Body: `{"completed":true}`})
		if rec.Code != http.StatusOK {
			t.Fatalf("completion %d: status = %d (body: %s)", i+1, rec.Code, rec.Body.String())
		}
		requireSchema(t, rec, "Completion")
	}
	var rows int
	if err := e.Pool.QueryRow(e.Ctx,
		`SELECT COUNT(*)::int FROM todo_completions WHERE todo_id = $1`, todo.ID).Scan(&rows); err != nil {
		t.Fatalf("counting completions: %v", err)
	}
	if rows != 1 {
		t.Errorf("%d completion rows after two identical PUTs, want 1", rows)
	}

	// Stating the desired state, not toggling: false means false.
	if rec := e.do(call{Method: http.MethodPut, Path: completion, Token: token, Body: `{"completed":false}`}); rec.Code != http.StatusOK {
		t.Fatalf("un-completing: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	if err := e.Pool.QueryRow(e.Ctx,
		`SELECT COUNT(*)::int FROM todo_completions WHERE todo_id = $1`, todo.ID).Scan(&rows); err != nil {
		t.Fatalf("counting completions: %v", err)
	}
	if rows != 0 {
		t.Errorf("%d completion rows after completed:false, want 0", rows)
	}

	// Deleting archives; every read endpoint must then behave as if it is gone.
	if rec := e.do(call{Method: http.MethodDelete, Path: fmt.Sprintf("/api/v1/todos/%d", todo.ID), Token: token}); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var list v1List[v1Todo]
	decodeJSON(t, e.get("/api/v1/todos", token), &list)
	if len(list.Data) != 0 {
		t.Errorf("an archived todo is still listed: %+v", list.Data)
	}
	requireProblem(t, e.patch(fmt.Sprintf("/api/v1/todos/%d", todo.ID), token, `{"name":"x"}`), http.StatusNotFound)
	requireProblem(t, e.do(call{Method: http.MethodPut, Path: completion, Token: token, Body: `{"completed":true}`}),
		http.StatusNotFound)
}

// TestV1TodoCompletionForAnUnknownTodoIs404 checks the ownership probe rather
// than letting an FK violation surface as a 500.
func TestV1TodoCompletionForAnUnknownTodoIs404(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeTodosWrite)

	rec := e.do(call{Method: http.MethodPut, Path: "/api/v1/todos/999999/completions/2026-08-05",
		Token: token, Body: `{"completed":true}`})
	requireProblem(t, rec, http.StatusNotFound)
}

// TestV1TodoLimitIs409 covers the MaxTodos branch.
func TestV1TodoLimitIs409(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeTodosWrite)

	for i := 0; i < service.MaxTodos; i++ {
		rec := e.post("/api/v1/todos", token,
			fmt.Sprintf(`{"name":"Todo %d","schedule":{"type":"daily"}}`, i))
		if rec.Code != http.StatusCreated {
			t.Fatalf("creating todo %d: status = %d (body: %s)", i, rec.Code, rec.Body.String())
		}
	}
	rec := e.post("/api/v1/todos", token, `{"name":"One too many","schedule":{"type":"daily"}}`)
	requireProblem(t, rec, http.StatusConflict)
}

// --- Saved foods ----------------------------------------------------------

// TestV1SavedFoodDuplicateNameIs409 covers the 23505 translation: the unique
// index on (user_id, lower(name)) must surface as a conflict, not a 500.
func TestV1SavedFoodDuplicateNameIs409(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeFoodsWrite)

	if rec := e.post("/api/v1/saved-foods", token, `{"name":"Banana","calories":105}`); rec.Code != http.StatusCreated {
		t.Fatalf("first create: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	requireProblem(t, e.post("/api/v1/saved-foods", token, `{"name":"Banana","calories":110}`), http.StatusConflict)
	// Case-insensitively, since the index is on lower(name).
	requireProblem(t, e.post("/api/v1/saved-foods", token, `{"name":"banana","calories":110}`), http.StatusConflict)
}

// TestV1SavedFoodValidation covers the name/calorie/macro rejection branches.
func TestV1SavedFoodValidation(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeFoodsWrite)

	cases := []struct{ name, body, param string }{
		{"no name", `{"calories":105}`, "name"},
		{"blank name", `{"name":"  ","calories":105}`, "name"},
		{"calories too high", fmt.Sprintf(`{"name":"X","calories":%d}`, MaxEntryCalories+1), "calories"},
		{"macro too high", fmt.Sprintf(`{"name":"X","protein_g":%d}`, MaxEntryMacro+1), "protein_g"},
		{"negative macro", `{"name":"X","carbs_g":-1}`, "carbs_g"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := requireProblem(t, e.post("/api/v1/saved-foods", token, c.body), http.StatusUnprocessableEntity)
			if len(p.InvalidParams) == 0 || p.InvalidParams[0].Name != c.param {
				t.Errorf("invalid_params = %+v, want it to name %s", p.InvalidParams, c.param)
			}
		})
	}
}

// TestV1SavedFoodPatchClearsWithNull is the Optional[T] path on a second
// resource, including the calorie column that is nullable here but not on an
// entry.
func TestV1SavedFoodPatchClearsWithNull(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeFoodsWrite)

	rec := e.post("/api/v1/saved-foods", token, `{"name":"Banana","emoji":"🍌","calories":105,"protein_g":1}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	requireSchema(t, rec, "SavedFood")
	var food v1SavedFood
	decodeJSON(t, rec, &food)

	upd := e.patch(fmt.Sprintf("/api/v1/saved-foods/%d", food.ID), token,
		`{"emoji":null,"calories":null,"protein_g":null}`)
	if upd.Code != http.StatusOK {
		t.Fatalf("PATCH: status = %d (body: %s)", upd.Code, upd.Body.String())
	}
	requireSchema(t, upd, "SavedFood")

	var after v1SavedFood
	decodeJSON(t, upd, &after)
	if after.Emoji != nil {
		t.Errorf("emoji = %q after an explicit null", *after.Emoji)
	}
	if after.Calories != nil {
		t.Errorf("calories = %d after an explicit null", *after.Calories)
	}
	if after.Macros.ProteinG != nil {
		t.Errorf("protein_g = %d after an explicit null", *after.Macros.ProteinG)
	}
	if after.Name != "Banana" {
		t.Errorf("name = %q; a PATCH that did not mention it must leave it alone", after.Name)
	}
}

// TestV1TrackSavedFoodValidation covers the quantity bounds and the
// "multiplying would exceed the entry limits" branch, which is the one that
// would otherwise hit the amount CHECK constraint as a 500.
func TestV1TrackSavedFoodValidation(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeFoodsWrite, service.ScopeEntriesWrite)

	rec := e.post("/api/v1/saved-foods", token, `{"name":"Big meal","calories":900,"protein_g":50}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var food v1SavedFood
	decodeJSON(t, rec, &food)
	path := fmt.Sprintf("/api/v1/saved-foods/%d/track", food.ID)

	for _, c := range []struct{ name, body string }{
		{"quantity zero", `{"quantity":0}`},
		{"quantity negative", `{"quantity":-1}`},
		{"quantity above 99", `{"quantity":100}`},
		{"quantity overflows the entry limits", `{"quantity":99}`},
		{"impossible date", `{"date":"2026-02-31"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := requireProblem(t, e.post(path, token, c.body), http.StatusUnprocessableEntity)
			if len(p.InvalidParams) == 0 {
				t.Errorf("invalid_params is empty: %+v", p)
			}
		})
	}

	requireProblem(t, e.post("/api/v1/saved-foods/999999/track", token, `{}`), http.StatusNotFound)

	// The happy path, to prove the rejections above are not the endpoint simply
	// refusing everything.
	ok := e.post(path, token, `{"date":"2026-08-05","quantity":1}`)
	if ok.Code != http.StatusCreated {
		t.Fatalf("tracking one serving: status = %d (body: %s)", ok.Code, ok.Body.String())
	}
	requireSchema(t, ok, "Entry")
}

// --- /me ------------------------------------------------------------------

// TestV1MeDescribesTheToken checks /me reports the scopes actually held, which
// is the only way a client can discover what it may do.
func TestV1MeDescribesTheToken(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesRead, service.ScopeWeightRead)

	rec := e.get("/api/v1/me", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	requireSchema(t, rec, "Me")

	var me v1Me
	decodeJSON(t, rec, &me)
	if me.User.ID != e.UserID {
		t.Errorf("user.id = %d, want %d", me.User.ID, e.UserID)
	}
	if me.User.Email != e.Email {
		t.Errorf("user.email = %q, want %q", me.User.Email, e.Email)
	}
	if len(me.Token.Scopes) != 2 {
		t.Errorf("token.scopes = %v, want the two the token was minted with", me.Token.Scopes)
	}
	if me.Server.Version == "" || me.Server.Today == "" {
		t.Errorf("server block is incomplete: %+v", me.Server)
	}
}

// TestV1MeSettingsValidation covers every rejection branch in UpdateMeV1.
func TestV1MeSettingsValidation(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeSettingsWrite)

	cases := []struct {
		name, body, param string
		status            int
	}{
		{"goal too low", `{"daily_goal":0}`, "daily_goal", http.StatusUnprocessableEntity},
		{"goal too high", fmt.Sprintf(`{"daily_goal":%d}`, MaxEntryCalories+1), "daily_goal", http.StatusUnprocessableEntity},
		{"unknown timezone", `{"timezone":"Mars/Olympus_Mons"}`, "timezone", http.StatusUnprocessableEntity},
		{"unknown weight unit", `{"weight_unit":"stone"}`, "weight_unit", http.StatusUnprocessableEntity},
		{"unsupported language", `{"language":"tlh"}`, "language", http.StatusUnprocessableEntity},
		{"nothing to update", `{}`, "", http.StatusBadRequest},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := requireProblem(t, e.patch("/api/v1/me", token, c.body), c.status)
			if c.param == "" {
				return
			}
			if len(p.InvalidParams) == 0 || p.InvalidParams[0].Name != c.param {
				t.Errorf("invalid_params = %+v, want it to name %s", p.InvalidParams, c.param)
			}
		})
	}
}

// TestV1MeSettingsApply checks the writes land and that /me reflects them,
// including the Optional[T] clear on daily_goal.
func TestV1MeSettingsApply(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeSettingsWrite)

	rec := e.patch("/api/v1/me", token, `{"daily_goal":2000,"timezone":"Europe/Berlin","weight_unit":"lb","language":"de"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	requireSchema(t, rec, "Me")

	var me v1Me
	decodeJSON(t, rec, &me)
	if me.User.DailyGoal == nil || *me.User.DailyGoal != 2000 {
		t.Errorf("daily_goal = %v, want 2000", me.User.DailyGoal)
	}
	if me.User.Timezone != "Europe/Berlin" {
		t.Errorf("timezone = %q", me.User.Timezone)
	}
	if me.User.WeightUnit != "lb" {
		t.Errorf("weight_unit = %q", me.User.WeightUnit)
	}
	if me.User.Language == nil || *me.User.Language != "de" {
		t.Errorf("language = %v, want de", me.User.Language)
	}

	// Explicit null clears the goal rather than leaving it alone.
	cleared := e.patch("/api/v1/me", token, `{"daily_goal":null}`)
	if cleared.Code != http.StatusOK {
		t.Fatalf("clearing the goal: status = %d (body: %s)", cleared.Code, cleared.Body.String())
	}
	decodeJSON(t, cleared, &me)
	if me.User.DailyGoal != nil {
		t.Errorf("daily_goal = %d after an explicit null", *me.User.DailyGoal)
	}

	var goal *int
	if err := e.Pool.QueryRow(e.Ctx, `SELECT daily_goal FROM users WHERE id = $1`, e.UserID).Scan(&goal); err != nil {
		t.Fatalf("reading daily_goal back: %v", err)
	}
	if goal != nil {
		t.Errorf("daily_goal in the database = %d, want NULL", *goal)
	}
}

// TestV1MeNeedsNoScopeButPatchDoes is invariant #5's neighbour: reading who you
// are is free, changing settings is not.
func TestV1MeNeedsNoScopeButPatchDoes(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesRead)

	if rec := e.get("/api/v1/me", token); rec.Code != http.StatusOK {
		t.Fatalf("GET /me with an unrelated scope: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	p := requireProblem(t, e.patch("/api/v1/me", token, `{"weight_unit":"lb"}`), http.StatusForbidden)
	if p.RequiredScope != service.ScopeSettingsWrite {
		t.Errorf("required_scope = %q, want %q", p.RequiredScope, service.ScopeSettingsWrite)
	}
}

// --- Disabled features ----------------------------------------------------

// TestV1DisabledFeaturesAre404 covers the nil-handler branches: a server built
// without barcode lookup or an AI provider must answer 404, not 500.
func TestV1DisabledFeaturesAre404(t *testing.T) {
	e := newV1Env(t)

	requireProblem(t, e.get("/api/v1/barcode/4006381333931", e.token(service.ScopeFoodsRead)),
		http.StatusNotFound)
	requireProblem(t, e.post("/api/v1/ai/estimate", e.token(service.ScopeAIEstimate), `{}`),
		http.StatusNotFound)
}
