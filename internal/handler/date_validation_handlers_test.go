package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func assertImpossibleDateRejected(t *testing.T, call func(http.ResponseWriter, *http.Request), path string) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, path+"?date=2026-02-31", nil)

	// These handlers all validate before touching the current user or database;
	// their zero-value dependencies make the test panic if that ordering regresses.
	call(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != "Invalid date" {
		t.Errorf("error = %q, want %q", body["error"], "Invalid date")
	}
}

func TestDateReadHandlersRejectImpossibleCalendarDates(t *testing.T) {
	t.Run("day entries", func(t *testing.T) {
		assertImpossibleDateRejected(t, (&EntriesHandler{}).DayEntries, "/entries/day")
	})
	t.Run("weight", func(t *testing.T) {
		assertImpossibleDateRejected(t, (&WeightHandler{}).WeightDay, "/weight/day")
	})
	t.Run("todos", func(t *testing.T) {
		assertImpossibleDateRejected(t, (&TodosHandler{}).DayTodos, "/api/todos/day")
	})
	t.Run("notes", func(t *testing.T) {
		assertImpossibleDateRejected(t, (&NotesHandler{}).Get, "/api/notes/day")
	})
}

func TestValidateTargetDateRejectsImpossibleCalendarDate(t *testing.T) {
	date := "2099-02-31"
	if validateTargetDate("date", &date, "2026-01-01") {
		t.Fatal("validateTargetDate accepted an impossible calendar date")
	}
}

func TestSanitizeDateRangeFallsBackFromImpossibleCalendarDates(t *testing.T) {
	start, end := sanitizeDateRange("2026-02-31", "2026-04-31", 14, "UTC")
	if !isValidDate(start) || !isValidDate(end) {
		t.Fatalf("sanitizeDateRange returned invalid range %q..%q", start, end)
	}
}
