package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/sse"
)

// deleteEntry drives the real POST /entries/{id}/delete for the seeded user.
func deleteEntryReq(t *testing.T, e *v1Env, id int) *httptest.ResponseRecorder {
	t.Helper()
	h := &EntriesHandler{Pool: e.Pool, Broker: sse.NewBroker(e.Pool)}
	r := chi.NewRouter()
	r.Post("/entries/{id}/delete", h.DeleteEntry)
	req := httptest.NewRequest(http.MethodPost, "/entries/"+strconv.Itoa(id)+"/delete", nil)
	req = req.WithContext(middleware.WithTestUser(req.Context(), &model.User{ID: e.UserID, Email: e.Email}))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

type storedEntry struct {
	ID        int
	Date      string
	Amount    int
	Name      *string
	CreatedAt time.Time
	Macros    [5]*int
}

func entriesOn(t *testing.T, e *v1Env, date string) []storedEntry {
	t.Helper()
	rows, err := e.Pool.Query(e.Ctx,
		`SELECT id, entry_date, amount, entry_name, created_at, protein_g, carbs_g, fat_g, fiber_g, sugar_g
		 FROM calorie_entries WHERE user_id = $1 AND entry_date = $2 ORDER BY id`, e.UserID, date)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var out []storedEntry
	for rows.Next() {
		var s storedEntry
		if err := rows.Scan(&s.ID, &s.Date, &s.Amount, &s.Name, &s.CreatedAt,
			&s.Macros[0], &s.Macros[1], &s.Macros[2], &s.Macros[3], &s.Macros[4]); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, s)
	}
	return out
}

// TestUndoDeleteRestoresTheOriginalEntry is the staging bug: an entry logged at
// 20:50, deleted at 20:51 and restored by Undo came back stamped 20:51. Undo
// now re-posts the `restore` body DeleteEntry returns, and that body must put
// back the very row that was deleted — its logged time first, but also every
// macro column, including fiber here, which the dashboard list would not even
// have shown had the user hidden it.
func TestUndoDeleteRestoresTheOriginalEntry(t *testing.T) {
	e := newV1Env(t)
	const date = "2026-08-01"
	logged := time.Date(2026, 8, 1, 20, 50, 12, 345678000, time.UTC)

	var origID int
	if err := e.Pool.QueryRow(e.Ctx,
		`INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name, created_at, protein_g, carbs_g, fat_g, fiber_g)
		 VALUES ($1, $2, 520, 'Pasta', $3, 20, 70, 15, 6) RETURNING id`,
		e.UserID, date, logged).Scan(&origID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := entriesOn(t, e, date)

	rec := deleteEntryReq(t, e, origID)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete: status %d (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		OK      bool           `json:"ok"`
		Restore map[string]any `json:"restore"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || !resp.OK || resp.Restore == nil {
		t.Fatalf("delete response has no restore body: %s", rec.Body.String())
	}
	if got := entriesOn(t, e, date); len(got) != 0 {
		t.Fatalf("row still present after delete: %+v", got)
	}

	body, _ := json.Marshal(resp.Restore)
	if rec := postEntry(t, e, string(body)); rec.Code != http.StatusOK {
		t.Fatalf("restore: status %d (%s)", rec.Code, rec.Body.String())
	}

	after := entriesOn(t, e, date)
	if len(after) != 1 {
		t.Fatalf("want exactly one restored row, got %d", len(after))
	}
	got, want := after[0], before[0]
	if !got.CreatedAt.Equal(logged) {
		t.Errorf("restored created_at = %s, want the original %s", got.CreatedAt.UTC().Format(time.RFC3339Nano), logged.Format(time.RFC3339Nano))
	}
	if got.Date != want.Date || got.Amount != want.Amount || got.Name == nil || *got.Name != *want.Name {
		t.Errorf("restored date/amount/name = %s/%d/%v, want %s/%d/%v", got.Date, got.Amount, got.Name, want.Date, want.Amount, *want.Name)
	}
	for i := range want.Macros {
		g, w := got.Macros[i], want.Macros[i]
		if (g == nil) != (w == nil) || (g != nil && *g != *w) {
			t.Errorf("restored macro %s = %s, want %s", []string{"protein", "carbs", "fat", "fiber", "sugar"}[i], fmtIntPtr(g), fmtIntPtr(w))
		}
	}
	// No soft delete: the restore is a new row, so a new id.
	if got.ID == origID {
		t.Errorf("restored row reused id %d", origID)
	}

	// A second delete of the already-gone id is still a plain 404.
	if rec := deleteEntryReq(t, e, origID); rec.Code != http.StatusNotFound {
		t.Errorf("re-delete: status %d, want 404", rec.Code)
	}
}

// TestCreateEntryCreatedAtIsValidated pins the bounds of the new optional
// created_at: a past or near-now RFC 3339 instant is stored as given, anything
// else is a 400 that writes nothing, and leaving it out keeps the old default.
func TestCreateEntryCreatedAtIsValidated(t *testing.T) {
	e := newV1Env(t)
	const date = "2026-08-02"
	now := time.Now()

	for name, v := range map[string]string{
		"future":    `"` + now.Add(time.Hour).UTC().Format(time.RFC3339) + `"`,
		"garbage":   `"yesterday"`,
		"date only": `"2026-08-02"`,
		"number":    `1754000000`,
		"year 1800": `"1800-01-01T00:00:00Z"`,
	} {
		rec := postEntry(t, e, `{"entry_date":"`+date+`","amount":"100","created_at":`+v+`}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (%s)", name, rec.Code, rec.Body.String())
		}
	}
	if got := entriesOn(t, e, date); len(got) != 0 {
		t.Fatalf("a rejected created_at still wrote %d row(s)", len(got))
	}

	// Inside the clock-skew allowance, and with an offset: accepted as given.
	skew := now.Add(time.Minute).Truncate(time.Second)
	if rec := postEntry(t, e, `{"entry_date":"`+date+`","amount":"100","created_at":"`+skew.In(time.FixedZone("", 2*3600)).Format(time.RFC3339)+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("near-now created_at: status %d (%s)", rec.Code, rec.Body.String())
	}
	// Absent: the column default, i.e. about now.
	if rec := postEntry(t, e, `{"entry_date":"`+date+`","amount":"100"}`); rec.Code != http.StatusOK {
		t.Fatalf("no created_at: status %d (%s)", rec.Code, rec.Body.String())
	}
	got := entriesOn(t, e, date)
	if len(got) != 2 {
		t.Fatalf("want 2 rows, got %d", len(got))
	}
	if !got[0].CreatedAt.Equal(skew) {
		t.Errorf("near-now created_at stored as %s, want %s", got[0].CreatedAt, skew)
	}
	if d := time.Since(got[1].CreatedAt); d < -time.Minute || d > time.Minute {
		t.Errorf("default created_at %s is not about now", got[1].CreatedAt)
	}
}

// TestSavedFoodCreateRestoresRank: saved foods rank by use_count, then
// last_used_at, so an Undo that re-created a food with neither dropped it to
// the end of the chip row and lost its "N×" count. Create now takes both back.
func TestSavedFoodCreateRestoresRank(t *testing.T) {
	e := newV1Env(t)
	h := &SavedFoodsHandler{Pool: e.Pool, Broker: sse.NewBroker(e.Pool)}
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/saved-foods", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(middleware.WithTestUser(req.Context(), &model.User{ID: e.UserID, Email: e.Email}))
		rec := httptest.NewRecorder()
		h.Create(rec, req)
		return rec
	}

	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	for name, body := range map[string]string{
		"negative use_count":  `{"name":"A","amount":100,"use_count":-1}`,
		"garbage use_count":   `{"name":"A","amount":100,"use_count":"lots"}`,
		"future last_used_at": `{"name":"A","amount":100,"last_used_at":"` + future + `"}`,
		"garbage last_used":   `{"name":"A","amount":100,"last_used_at":"soon"}`,
	} {
		if rec := post(body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (%s)", name, rec.Code, rec.Body.String())
		}
	}

	lastUsed := time.Date(2026, 7, 30, 8, 15, 0, 0, time.UTC)
	if rec := post(`{"name":"Oats","amount":350,"use_count":7,"last_used_at":"` + lastUsed.Format(time.RFC3339) + `"}`); rec.Code != http.StatusOK {
		t.Fatalf("restore create: status %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := post(`{"name":"Plain","amount":100}`); rec.Code != http.StatusOK {
		t.Fatalf("plain create: status %d (%s)", rec.Code, rec.Body.String())
	}

	check := func(name string, wantCount int, wantLast *time.Time) {
		t.Helper()
		var n int
		var last *time.Time
		if err := e.Pool.QueryRow(e.Ctx, `SELECT use_count, last_used_at FROM saved_foods WHERE user_id = $1 AND name = $2`,
			e.UserID, name).Scan(&n, &last); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if n != wantCount {
			t.Errorf("%s: use_count = %d, want %d", name, n, wantCount)
		}
		if (last == nil) != (wantLast == nil) || (last != nil && !last.Equal(*wantLast)) {
			t.Errorf("%s: last_used_at = %v, want %v", name, last, wantLast)
		}
	}
	check("Oats", 7, &lastUsed)
	check("Plain", 0, nil)
	var stored int
	e.Pool.QueryRow(e.Ctx, `SELECT COUNT(*) FROM saved_foods WHERE user_id = $1`, e.UserID).Scan(&stored)
	if stored != 2 {
		t.Errorf("stored %d saved foods, want 2 (a rejected create wrote a row)", stored)
	}
}

func fmtIntPtr(p *int) string {
	if p == nil {
		return "NULL"
	}
	return strconv.Itoa(*p)
}
