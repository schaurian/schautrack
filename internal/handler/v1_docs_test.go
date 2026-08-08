package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestV1DocsIsPublicHTML mirrors the /openapi.json test: the reference page
// must be readable without a token — it is how a prospective client learns
// what a token would buy — and must be HTML, not JSON.
func TestV1DocsIsPublicHTML(t *testing.T) {
	h := &V1Handler{BuildVersion: "test", BaseURL: "https://example.test"}
	router := h.MountAPIV1(nil)

	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /docs = %d, want 200. Body: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<!doctype html>") {
		t.Error("body is not an HTML document")
	}
	// The page must describe this instance, not the canonical host.
	if !strings.Contains(body, "https://example.test/api/v1") {
		t.Error("page does not carry this instance's servers URL")
	}

	// Cache stability: a second request must serve identical bytes.
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/docs", nil))
	if rec2.Body.String() != body {
		t.Error("two requests rendered different pages; the page must be cached per handler")
	}
}
