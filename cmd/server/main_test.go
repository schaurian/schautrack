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

func TestViteAssetsCacheForOneYear(t *testing.T) {
	clientDir := t.TempDir()
	for path, body := range map[string][]byte{
		"assets/index-abc12345.js":   []byte("export {}"),
		"assets/index-def67890.css":  []byte("body {}"),
		"assets/noto-ghi01234.woff2": []byte("font"),
	} {
		filePath := filepath.Join(clientDir, path)
		if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filePath, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	handler := spaFallback(clientDir, filepath.Join(clientDir, "no-such-public"))
	for _, path := range []string{
		"/assets/index-abc12345.js",
		"/assets/index-def67890.css",
		"/assets/noto-ghi01234.woff2",
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got, want := rec.Header().Get("Cache-Control"), "public, max-age=31536000, immutable"; got != want {
				t.Errorf("Cache-Control = %q, want %q", got, want)
			}
		})
	}
}

// TestLLMSTxtServedFromPublicStaticPath exercises the same SPA fallback that
// production uses for files in public/. Keeping llms.txt there makes it
// available without a separate handler or deployment-specific route.
func TestLLMSTxtServedFromPublicStaticPath(t *testing.T) {
	clientDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(clientDir, "index.html"), []byte("<!doctype html><title>app</title>"), 0o644); err != nil {
		t.Fatal(err)
	}

	handler := spaFallback(clientDir, filepath.Join("..", "..", "public"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/llms.txt", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if contentType := rec.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", contentType)
	}
	if !strings.HasPrefix(rec.Body.String(), "# Schautrack\n") {
		t.Errorf("llms.txt did not serve its expected document (body: %.80s)", rec.Body.String())
	}
}

// A hashed asset that no longer exists must 404 rather than fall back to
// index.html. Serving HTML with a 200 for a missing chunk is what turns a
// routine deploy — a tab still referencing the previous build's filenames —
// into "Failed to fetch dynamically imported module", because the browser gets
// markup where a JS module should be.
func TestMissingAssetReturns404NotIndexHTML(t *testing.T) {
	clientDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(clientDir, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	indexHTML := []byte("<!doctype html><title>app</title>")
	if err := os.WriteFile(filepath.Join(clientDir, "index.html"), indexHTML, 0o644); err != nil {
		t.Fatal(err)
	}
	handler := spaFallback(clientDir, filepath.Join(clientDir, "no-such-public"))

	t.Run("missing chunk 404s", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/assets/Admin-deadbeef.js", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (body: %.60s)", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "text/html") {
			t.Fatalf("missing asset answered with %s — a module request must not receive HTML", ct)
		}
	})

	t.Run("client route still falls back to index.html", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/settings", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 for an SPA route", rec.Code)
		}
		if !bytes.Equal(bytes.TrimSpace(rec.Body.Bytes()), indexHTML) {
			t.Fatalf("SPA route did not receive index.html, got %.60s", rec.Body.String())
		}
	})
}
