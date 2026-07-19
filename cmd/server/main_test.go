package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// TestSPACompression verifies the static SPA bundle is served gzip-compressed
// when the client advertises it, and served untouched otherwise. This guards
// the fix for the "667 KB SPA bundle served uncompressed" finding (issue #148).
func TestSPACompression(t *testing.T) {
	// A representative, compressible JS asset. Repetition guarantees gzip
	// shrinks it well below the raw size.
	jsBody := []byte(strings.Repeat("export function add(a,b){return a+b;}\n", 400))

	clientDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(clientDir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	assetPath := filepath.Join(clientDir, "assets", "index-test.js")
	if err := os.WriteFile(assetPath, jsBody, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clientDir, "index.html"), []byte("<!doctype html><title>t</title>"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Same wiring as main(): Compress wraps the file server only.
	handler := chimw.Compress(5)(spaFallback(clientDir, filepath.Join(clientDir, "no-such-public")))

	t.Run("gzip when advertised", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/assets/index-test.js", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		res := rec.Result()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", res.StatusCode)
		}
		if got := res.Header.Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want %q", got, "gzip")
		}
		if !strings.Contains(res.Header.Get("Vary"), "Accept-Encoding") {
			t.Errorf("Vary = %q, want it to contain Accept-Encoding", res.Header.Get("Vary"))
		}
		if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
			t.Errorf("Content-Type = %q, want text/javascript…", ct)
		}

		gr, err := gzip.NewReader(res.Body)
		if err != nil {
			t.Fatalf("gzip.NewReader: %v", err)
		}
		got, err := io.ReadAll(gr)
		if err != nil {
			t.Fatalf("read gzip body: %v", err)
		}
		if !bytes.Equal(got, jsBody) {
			t.Errorf("decompressed body mismatch: got %d bytes, want %d", len(got), len(jsBody))
		}
	})

	t.Run("identity when not advertised", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/assets/index-test.js", nil)
		// No Accept-Encoding header.
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		res := rec.Result()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", res.StatusCode)
		}
		if got := res.Header.Get("Content-Encoding"); got != "" {
			t.Fatalf("Content-Encoding = %q, want empty (no compression)", got)
		}
		body, _ := io.ReadAll(res.Body)
		if !bytes.Equal(body, jsBody) {
			t.Errorf("body mismatch: got %d bytes, want %d", len(body), len(jsBody))
		}
	})
}
