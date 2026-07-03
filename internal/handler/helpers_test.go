package handler

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadJSONLimit_DecodesWithinLimit(t *testing.T) {
	var dst struct {
		Name string `json:"name"`
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"apple"}`))
	w := httptest.NewRecorder()

	if err := ReadJSONLimit(w, r, &dst, 1024); err != nil {
		t.Fatalf("ReadJSONLimit: %v", err)
	}
	if dst.Name != "apple" {
		t.Errorf("Name = %q, want %q", dst.Name, "apple")
	}
}

// TestReadJSONLimit_OversizeIsMaxBytesError guards the 413 mapping: bodies
// over the limit must surface as *http.MaxBytesError, not be silently
// truncated into a generic JSON parse error.
func TestReadJSONLimit_OversizeIsMaxBytesError(t *testing.T) {
	var dst map[string]any
	body := `{"pad":"` + strings.Repeat("x", 64) + `"}`
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	w := httptest.NewRecorder()

	err := ReadJSONLimit(w, r, &dst, 16)
	if err == nil {
		t.Fatal("expected error for oversize body")
	}
	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) {
		t.Fatalf("error = %T (%v), want *http.MaxBytesError", err, err)
	}
	if maxErr.Limit != 16 {
		t.Errorf("Limit = %d, want 16", maxErr.Limit)
	}
}

// ReadJSONLimit must also work with a nil ResponseWriter (used by ReadJSON).
func TestReadJSONLimit_NilWriter(t *testing.T) {
	var dst map[string]any
	r := httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", 64)))

	err := ReadJSONLimit(nil, r, &dst, 16)
	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) {
		t.Fatalf("error = %T (%v), want *http.MaxBytesError", err, err)
	}
}

func TestReadJSON_StillDecodes(t *testing.T) {
	var dst struct {
		Amount int `json:"amount"`
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"amount":420}`))
	if err := ReadJSON(r, &dst); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if dst.Amount != 420 {
		t.Errorf("Amount = %d, want 420", dst.Amount)
	}
}
