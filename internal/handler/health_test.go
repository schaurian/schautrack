package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpointShuttingDown(t *testing.T) {
	// Mark shutting down
	shuttingDown.Store(true)
	defer shuttingDown.Store(false)

	h := Health(nil, "test")
	r := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "shutting_down" {
		t.Errorf("status = %v, want shutting_down", resp["status"])
	}
}

func TestHealthEndpointShuttingDown_IncludesVersionAndApp(t *testing.T) {
	shuttingDown.Store(true)
	defer shuttingDown.Store(false)

	h := Health(nil, "v1.0.0")
	r := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["version"] != "v1.0.0" {
		t.Errorf("version = %v, want v1.0.0", resp["version"])
	}
	if resp["app"] != "schautrack" {
		t.Errorf("app = %v, want schautrack", resp["app"])
	}
}
