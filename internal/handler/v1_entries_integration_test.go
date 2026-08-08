package handler

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"schautrack/internal/service"
)

// Behaviour of /api/v1/entries: validation, the full create/read/update/delete
// round trip, keyset pagination across a page boundary, and the Optional[T]
// clear-a-macro path all the way into the SQL.

// createEntry POSTs an entry and returns the decoded response, failing the test
// if it was not created.
func (e *v1Env) createEntry(token, body string) v1Entry {
	e.t.Helper()

	rec := e.post("/api/v1/entries", token, body)
	if rec.Code != http.StatusCreated {
		e.t.Fatalf("POST /entries %s: status = %d, want 201 (body: %s)", body, rec.Code, rec.Body.String())
	}
	var out v1Entry
	decodeJSON(e.t, rec, &out)
	return out
}

// TestV1CreateEntryRejectsOutOfRangeCalories is the case the issue names first:
// an out-of-range calorie value must be a 422 that says which field is wrong,
// not a 500 from the amount CHECK constraint.
func TestV1CreateEntryRejectsOutOfRangeCalories(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	for _, body := range []string{
		fmt.Sprintf(`{"calories":%d}`, MaxEntryCalories+1),
		fmt.Sprintf(`{"calories":%d}`, -(MaxEntryCalories + 1)),
		`{"calories":1000000}`,
	} {
		t.Run(body, func(t *testing.T) {
			rec := e.post("/api/v1/entries", token, body)

			p := requireProblem(t, rec, http.StatusUnprocessableEntity)
			if len(p.InvalidParams) == 0 {
				t.Fatal("invalid_params is empty; a client cannot highlight the offending field")
			}
			if p.InvalidParams[0].Name != "calories" {
				t.Errorf("invalid_params[0].name = %q, want %q", p.InvalidParams[0].Name, "calories")
			}
			if p.InvalidParams[0].Reason == "" {
				t.Error("invalid_params[0].reason is empty")
			}
		})
	}
}

// TestV1CreateEntryReportsEveryBadMacroAtOnce covers validateMacros's documented
// promise: collect ALL violations rather than making the caller fix them one
// round trip at a time.
func TestV1CreateEntryReportsEveryBadMacroAtOnce(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	rec := e.post("/api/v1/entries", token,
		fmt.Sprintf(`{"protein_g":%d,"carbs_g":-1,"fat_g":%d}`, MaxEntryMacro+1, MaxEntryMacro+50))

	p := requireProblem(t, rec, http.StatusUnprocessableEntity)
	got := map[string]bool{}
	for _, ip := range p.InvalidParams {
		got[ip.Name] = true
	}
	for _, want := range []string{"protein_g", "carbs_g", "fat_g"} {
		if !got[want] {
			t.Errorf("invalid_params does not mention %s: %+v", want, p.InvalidParams)
		}
	}
}

// TestV1CreateEntryRejectsAnImpossibleDate: 2026-02-31 parses as a shape but is
// not a calendar date. Postgres would reject it with a query error, i.e. a 500.
func TestV1CreateEntryRejectsAnImpossibleDate(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	for _, date := range []string{"2026-02-31", "2026-13-01", "2026-8-5", "not-a-date", "1899-12-31"} {
		t.Run(date, func(t *testing.T) {
			rec := e.post("/api/v1/entries", token,
				fmt.Sprintf(`{"calories":100,"date":%q}`, date))

			p := requireProblem(t, rec, http.StatusUnprocessableEntity)
			if len(p.InvalidParams) == 0 || p.InvalidParams[0].Name != "date" {
				t.Errorf("invalid_params = %+v, want it to name date", p.InvalidParams)
			}
		})
	}
}

// TestV1CreateEntryNeedsSomething checks the "an entry needs at least a calorie
// value or one macro" branch.
func TestV1CreateEntryNeedsSomething(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	rec := e.post("/api/v1/entries", token, `{"name":"Just a label"}`)
	requireProblem(t, rec, http.StatusUnprocessableEntity)
}

// TestV1EntryRoundTrip walks the resource lifecycle the way a client would,
// including following the Location header the create response advertises.
func TestV1EntryRoundTrip(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	rec := e.post("/api/v1/entries", token,
		`{"date":"2026-08-05","calories":450,"name":"Porridge","protein_g":12,"carbs_g":60}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	requireSchema(t, rec, "Entry")

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatal("no Location header on 201; a client cannot address what it just created")
	}

	var created v1Entry
	decodeJSON(t, rec, &created)
	if created.Calories != 450 {
		t.Errorf("calories = %d, want 450", created.Calories)
	}
	if created.Macros.ProteinG == nil || *created.Macros.ProteinG != 12 {
		t.Errorf("protein_g = %v, want 12", created.Macros.ProteinG)
	}
	if created.Macros.FatG != nil {
		t.Errorf("fat_g = %v, want null — an unrecorded macro must not read as 0", *created.Macros.FatG)
	}

	// The Location header must be usable verbatim.
	got := e.get(location, token)
	if got.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200 (body: %s)", location, got.Code, got.Body.String())
	}
	requireSchema(t, got, "Entry")
	var fetched v1Entry
	decodeJSON(t, got, &fetched)
	if fetched.ID != created.ID {
		t.Errorf("Location pointed at entry %d, want %d", fetched.ID, created.ID)
	}

	// PATCH, then DELETE, then confirm it is gone and that deleting twice 404s
	// rather than silently succeeding.
	upd := e.patch(location, token, `{"calories":500,"name":"Porridge with berries"}`)
	if upd.Code != http.StatusOK {
		t.Fatalf("PATCH: status = %d, want 200 (body: %s)", upd.Code, upd.Body.String())
	}
	requireSchema(t, upd, "Entry")

	del := e.do(call{Method: http.MethodDelete, Path: location, Token: token})
	if del.Code != http.StatusNoContent {
		t.Fatalf("DELETE: status = %d, want 204 (body: %s)", del.Code, del.Body.String())
	}
	if body := del.Body.String(); body != "" {
		t.Errorf("204 carried a body: %q", body)
	}
	requireProblem(t, e.get(location, token), http.StatusNotFound)
	requireProblem(t, e.do(call{Method: http.MethodDelete, Path: location, Token: token}), http.StatusNotFound)
}

// TestV1PatchClearsAMacroEndToEnd is the assertion v1_optional_test.go cannot
// make: the decoder distinguishing null from absent is only useful if the SQL
// that follows actually writes NULL. This checks the column, not the struct.
func TestV1PatchClearsAMacroEndToEnd(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	entry := e.createEntry(token, `{"date":"2026-08-05","calories":450,"name":"Porridge","protein_g":12,"fiber_g":5}`)

	// An absent key must leave the macro alone...
	rec := e.patch(fmt.Sprintf("/api/v1/entries/%d", entry.ID), token, `{"calories":460}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH {calories}: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var afterAbsent v1Entry
	decodeJSON(t, rec, &afterAbsent)
	if afterAbsent.Macros.ProteinG == nil || *afterAbsent.Macros.ProteinG != 12 {
		t.Fatalf("protein_g = %v after a PATCH that did not mention it; absent must mean 'leave alone'",
			afterAbsent.Macros.ProteinG)
	}

	// ...and an explicit null must clear it.
	rec = e.patch(fmt.Sprintf("/api/v1/entries/%d", entry.ID), token, `{"protein_g":null}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH {protein_g:null}: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	requireSchema(t, rec, "Entry")
	var afterNull v1Entry
	decodeJSON(t, rec, &afterNull)
	if afterNull.Macros.ProteinG != nil {
		t.Errorf("protein_g = %d in the response after an explicit null", *afterNull.Macros.ProteinG)
	}
	if afterNull.Macros.FiberG == nil || *afterNull.Macros.FiberG != 5 {
		t.Errorf("fiber_g = %v; clearing protein must not touch the other macros", afterNull.Macros.FiberG)
	}

	// The column itself, not just the response the handler assembled.
	var protein *int
	if err := e.Pool.QueryRow(e.Ctx,
		`SELECT protein_g FROM calorie_entries WHERE id = $1`, entry.ID).Scan(&protein); err != nil {
		t.Fatalf("reading protein_g back: %v", err)
	}
	if protein != nil {
		t.Errorf("protein_g in the database = %d, want NULL — the response lied about clearing it", *protein)
	}
}

// TestV1PatchClearsTheName covers the Optional[string] path, which writes NULL
// through a different branch than the macros do.
func TestV1PatchClearsTheName(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	entry := e.createEntry(token, `{"date":"2026-08-05","calories":450,"name":"Porridge"}`)

	rec := e.patch(fmt.Sprintf("/api/v1/entries/%d", entry.ID), token, `{"name":null}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var out v1Entry
	decodeJSON(t, rec, &out)
	if out.Name != nil {
		t.Errorf("name = %q after an explicit null", *out.Name)
	}
}

// TestV1PatchWithNothingToDoIs400 — an empty patch is a client mistake, and
// answering 200 would let a typo'd field name look like a successful write.
func TestV1PatchWithNothingToDoIs400(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	entry := e.createEntry(token, `{"calories":100}`)
	requireProblem(t, e.patch(fmt.Sprintf("/api/v1/entries/%d", entry.ID), token, `{}`), http.StatusBadRequest)
}

// TestV1EntriesAreScopedToTheOwner: another account's entry must read as
// missing, not as forbidden — 403 would confirm the id exists.
func TestV1EntriesAreScopedToTheOwner(t *testing.T) {
	e := newV1Env(t)

	otherID, _ := e.seedUser("-other")
	otherToken := e.tokenFor(otherID, service.ScopeEntriesWrite)
	mine := e.token(service.ScopeEntriesWrite)

	rec := e.post("/api/v1/entries", otherToken, `{"date":"2026-08-05","calories":450}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seeding the other account's entry: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var theirs v1Entry
	decodeJSON(t, rec, &theirs)

	path := fmt.Sprintf("/api/v1/entries/%d", theirs.ID)
	requireProblem(t, e.get(path, mine), http.StatusNotFound)
	requireProblem(t, e.patch(path, mine, `{"calories":1}`), http.StatusNotFound)
	requireProblem(t, e.do(call{Method: http.MethodDelete, Path: path, Token: mine}), http.StatusNotFound)

	// And the collection must not include it either.
	list := e.get("/api/v1/entries", mine)
	var page v1List[v1Entry]
	decodeJSON(t, list, &page)
	for _, en := range page.Data {
		if en.ID == theirs.ID {
			t.Fatalf("GET /entries returned another account's entry %d", theirs.ID)
		}
	}
}

// TestV1EntriesKeysetPaginationCrossesADateBoundary is the pagination assertion
// the issue asks for: walk a paginated collection using next_cursor verbatim,
// across a page boundary that falls between two dates, and check the pages
// concatenate to exactly the full set in the documented order — no repeats, no
// skips.
func TestV1EntriesKeysetPaginationCrossesADateBoundary(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	// Three entries on the later day, two on the earlier one, so a limit of 2
	// puts the second page's boundary in the middle of the date change.
	var want []int
	for _, spec := range []struct {
		date     string
		calories int
	}{
		{"2026-08-05", 101}, {"2026-08-05", 102}, {"2026-08-05", 103},
		{"2026-08-04", 201}, {"2026-08-04", 202},
	} {
		en := e.createEntry(token, fmt.Sprintf(`{"date":%q,"calories":%d}`, spec.date, spec.calories))
		want = append(want, en.ID)
	}
	// Documented order is entry_date DESC, id DESC.
	expected := []int{want[2], want[1], want[0], want[4], want[3]}

	var got []int
	path := "/api/v1/entries?limit=2"
	for page := 1; ; page++ {
		if page > 10 {
			t.Fatal("pagination did not terminate after 10 pages")
		}
		rec := e.get(path, token)
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d: status = %d (body: %s)", page, rec.Code, rec.Body.String())
		}
		requireSchema(t, rec, "EntryList")

		var body v1List[v1Entry]
		decodeJSON(t, rec, &body)
		if body.HasMore == nil {
			t.Fatalf("page %d has no has_more; a client cannot tell whether to keep going", page)
		}
		for _, en := range body.Data {
			got = append(got, en.ID)
		}

		if !*body.HasMore {
			if body.NextCursor != nil {
				t.Errorf("the last page still advertised next_cursor = %q", *body.NextCursor)
			}
			break
		}
		if body.NextCursor == nil {
			t.Fatalf("page %d says has_more but carries no next_cursor", page)
		}
		if len(body.Data) != 2 {
			t.Errorf("page %d returned %d rows, want the requested limit of 2", page, len(body.Data))
		}
		// Verbatim, as the cursor's own error message instructs.
		path = "/api/v1/entries?limit=2&cursor=" + *body.NextCursor
	}

	if len(got) != len(expected) {
		t.Fatalf("paged through %d entries, want %d (got %v, want %v)", len(got), len(expected), got, expected)
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("paged order = %v, want %v", got, expected)
		}
	}
}

// TestV1EntriesCursorFromOneResponseIsAcceptedVerbatim isolates the round trip
// of the cursor itself: whatever the server emits, the server must accept.
func TestV1EntriesCursorFromOneResponseIsAcceptedVerbatim(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	for i := 0; i < 3; i++ {
		e.createEntry(token, fmt.Sprintf(`{"date":"2026-08-05","calories":%d}`, 100+i))
	}

	rec := e.get("/api/v1/entries?limit=1", token)
	var first v1List[v1Entry]
	decodeJSON(t, rec, &first)
	if first.NextCursor == nil {
		t.Fatal("no next_cursor on a page that has more")
	}

	// Not re-encoded, not URL-mangled: exactly the string that came back.
	next := e.get("/api/v1/entries?limit=1&cursor="+*first.NextCursor, token)
	if next.Code != http.StatusOK {
		t.Fatalf("the server rejected its own next_cursor %q: status = %d (body: %s)",
			*first.NextCursor, next.Code, next.Body.String())
	}
	var second v1List[v1Entry]
	decodeJSON(t, next, &second)
	if len(second.Data) != 1 {
		t.Fatalf("second page has %d rows, want 1", len(second.Data))
	}
	if second.Data[0].ID == first.Data[0].ID {
		t.Errorf("the cursor returned the same row again (id %d) — the page did not advance", second.Data[0].ID)
	}
}

// TestV1EntriesLimitIsClampedNotRejected: over-large limits clamp to
// maxPageSize, which is what stops a client asking for 100000 rows.
func TestV1EntriesLimitIsClampedNotRejected(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesRead)

	rec := e.get(fmt.Sprintf("/api/v1/entries?limit=%d", maxPageSize*100), token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — an over-large limit clamps (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestV1EntriesDateFiltersAreValidated covers the query-parameter branches of
// ListEntries, including the mutually exclusive date/from-to pair.
func TestV1EntriesDateFiltersAreValidated(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesRead)

	cases := []struct {
		query  string
		status int
	}{
		{"?date=2026-08-05", http.StatusOK},
		{"?from=2026-08-01&to=2026-08-31", http.StatusOK},
		{"?date=2026-08-05&from=2026-08-01", http.StatusBadRequest},
		{"?from=2026-08-31&to=2026-08-01", http.StatusUnprocessableEntity},
		{"?date=2026-02-31", http.StatusBadRequest},
		{"?limit=0", http.StatusBadRequest},
		{"?cursor=not-base64", http.StatusBadRequest},
		// Decodes as base64 but is not a date,id pair.
		{"?cursor=Zm9vYmFy", http.StatusBadRequest},
	}

	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			rec := e.get("/api/v1/entries"+c.query, token)
			if rec.Code != c.status {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, c.status, rec.Body.String())
			}
			if c.status >= 400 {
				requireProblemShape(t, rec)
			}
		})
	}
}

// TestV1EntryErrorsCarryAnInstance checks the RFC 9457 `instance` member is
// populated from the request path, which is what makes a pasted error report
// self-locating.
func TestV1EntryErrorsCarryAnInstance(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	p := requireProblem(t, e.post("/api/v1/entries", token, `{"calories":999999}`),
		http.StatusUnprocessableEntity)
	if !strings.HasSuffix(p.Instance, "/entries") {
		t.Errorf("instance = %q, want the request path", p.Instance)
	}
}

// TestV1ProblemBodiesMatchTheDocumentedSchema closes the loop between the error
// paths these tests exercise and the Problem schema the contract publishes.
func TestV1ProblemBodiesMatchTheDocumentedSchema(t *testing.T) {
	e := newV1Env(t)

	cases := map[string]call{
		"unauthorized":       {Method: http.MethodGet, Path: "/api/v1/entries"},
		"insufficient scope": {Method: http.MethodGet, Path: "/api/v1/entries", Token: e.token(service.ScopeWeightRead)},
		"not found":          {Method: http.MethodGet, Path: "/api/v1/entries/999999", Token: e.token(service.ScopeEntriesRead)},
		"validation failed":  {Method: http.MethodPost, Path: "/api/v1/entries", Token: e.token(service.ScopeEntriesWrite), Body: `{"calories":999999}`},
		"bad request":        {Method: http.MethodGet, Path: "/api/v1/entries?limit=x", Token: e.token(service.ScopeEntriesRead)},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rec := e.do(c)
			requireProblemShape(t, rec)
			requireSchema(t, rec, "Problem")
		})
	}
}
