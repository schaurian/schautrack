package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// The nonexistent-row → 404 branch of DeleteEntry/WeightDelete needs a live
// database (RowsAffected on a real DELETE), so these tests cover the
// validation path that is reachable without Postgres and pin the shared
// {ok:false, error:"..."} envelope.

func TestDeleteEntry_InvalidID(t *testing.T) {
	h := &EntriesHandler{} // nil pool: invalid id must fail before any DB access
	router := chi.NewRouter()
	router.Post("/entries/{id}/delete", h.DeleteEntry)

	r := httptest.NewRequest("POST", "/entries/notanumber/delete", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if msg, _ := resp["error"].(string); msg == "" {
		t.Errorf("expected non-empty 'error' key, got %q", w.Body.String())
	}
}

func TestWeightDelete_InvalidID(t *testing.T) {
	h := &WeightHandler{} // nil pool: invalid id must fail before any DB access
	router := chi.NewRouter()
	router.Post("/weight/{id}/delete", h.WeightDelete)

	r := httptest.NewRequest("POST", "/weight/notanumber/delete", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if msg, _ := resp["error"].(string); msg == "" {
		t.Errorf("expected non-empty 'error' key, got %q", w.Body.String())
	}
}
