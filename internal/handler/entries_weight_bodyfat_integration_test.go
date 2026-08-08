package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/sse"
)

// postEntry drives the real POST /entries handler for the seeded user and
// returns the recorder. Uses the same pool the v1 harness builds, which is
// database.NewPool — so the DATE codec production installs is present.
func postEntry(t *testing.T, e *v1Env, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := &EntriesHandler{Pool: e.Pool, Broker: sse.NewBroker(e.Pool)}

	req := httptest.NewRequest(http.MethodPost, "/entries", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithTestUser(req.Context(),
		&model.User{ID: e.UserID, Email: e.Email}))

	rec := httptest.NewRecorder()
	h.CreateEntry(rec, req)
	return rec
}

func weightRow(t *testing.T, e *v1Env, date string) (weight *float64, bodyFat *float64, found bool) {
	t.Helper()
	err := e.Pool.QueryRow(e.Ctx,
		`SELECT weight, body_fat FROM weight_entries WHERE user_id = $1 AND entry_date = $2`,
		e.UserID, date).Scan(&weight, &bodyFat)
	if err != nil {
		return nil, nil, false
	}
	return weight, bodyFat, true
}

// TestCreateEntryRejectsAnUnparseableWeight pins #319. The weight used to be
// dropped when it did not parse, leaving hasWeight false, so the request
// answered 200 having stored nothing — the user typed a weight, saw success,
// and it was not there. Every sibling field on this handler already rejects
// what it cannot parse.
func TestCreateEntryRejectsAnUnparseableWeight(t *testing.T) {
	e := newV1Env(t)

	for _, w := range []string{"abc", "-5", "0", "99999"} {
		rec := postEntry(t, e, `{"entry_date":"2026-08-05","weight":"`+w+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("weight %q: status = %d, want 400 (body: %s)", w, rec.Code, rec.Body.String())
		}
		if _, _, found := weightRow(t, e, "2026-08-05"); found {
			t.Errorf("weight %q: a row was written for a rejected weight", w)
		}
	}

	// A parseable weight still works, so the rejection is not over-broad.
	rec := postEntry(t, e, `{"entry_date":"2026-08-05","weight":"82.4"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid weight: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	w, _, found := weightRow(t, e, "2026-08-05")
	if !found || w == nil || *w != 82.4 {
		t.Errorf("stored weight = %v (found=%v), want 82.4", w, found)
	}
}

// TestCreateEntryStoresABodyFatWithoutAWeight pins #327. body_fat was parsed
// and range-checked — an out-of-range value got a 400 — but only written when a
// weight came along in the same request. So a GOOD body fat returned 200 and
// was thrown away while a BAD one was rejected: a validation error for the
// wrong value and a silent success for the right one.
func TestCreateEntryStoresABodyFatWithoutAWeight(t *testing.T) {
	e := newV1Env(t)
	const date = "2026-08-06"

	// With no weight logged for the date there is nothing to attach the
	// reading to, and inventing a weight would be worse than refusing.
	rec := postEntry(t, e, `{"entry_date":"`+date+`","body_fat":"24.3"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("body fat with no weight row: status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}

	// Log a weight, then send body fat alone: it must land.
	if rec := postEntry(t, e, `{"entry_date":"`+date+`","weight":"80"}`); rec.Code != http.StatusOK {
		t.Fatalf("seeding the weight: status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	rec = postEntry(t, e, `{"entry_date":"`+date+`","body_fat":"24.3"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("body fat alone: status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	w, bf, found := weightRow(t, e, date)
	if !found {
		t.Fatal("no weight row after a body-fat-only save")
	}
	if bf == nil || *bf != 24.3 {
		t.Errorf("stored body_fat = %v, want 24.3 — the reading was discarded", bf)
	}
	if w == nil || *w != 80 {
		t.Errorf("stored weight = %v, want 80 — a body-fat-only save must not disturb it", w)
	}

	// And an out-of-range value is still a 400, so the fix did not widen what
	// is accepted.
	if rec := postEntry(t, e, `{"entry_date":"`+date+`","body_fat":"99"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("out-of-range body fat: status = %d, want 400", rec.Code)
	}
}

// TestCreateEntryStillRejectsAnEmptyRequest checks the "Invalid entry data"
// guard did not get lost when bodyFat.Set joined the content test.
func TestCreateEntryStillRejectsAnEmptyRequest(t *testing.T) {
	e := newV1Env(t)
	rec := postEntry(t, e, `{"entry_date":"2026-08-07"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty entry: status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "Invalid entry data" {
		t.Errorf("error = %v, want \"Invalid entry data\"", body["error"])
	}
}
