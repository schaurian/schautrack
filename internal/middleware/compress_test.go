package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCompressJSONGzipsJSONResponses(t *testing.T) {
	body := `{"ok":true,"entries":[` + strings.Repeat(`{"name":"Oatmeal","amount":350},`, 200) + `{}]}`
	h := CompressJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	if rec.Body.Len() >= len(body) {
		t.Fatalf("compressed body is %d bytes, not smaller than the %d-byte original", rec.Body.Len(), len(body))
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(got) != body {
		t.Fatal("decompressed body differs from the original")
	}
}

func TestCompressJSONLeavesIdentityClientsAlone(t *testing.T) {
	h := CompressJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/me", nil))

	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("Content-Encoding = %q for a client that sent no Accept-Encoding", got)
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// The SSE stream must reach the browser event by event. A compressor in front
// of it buffers until its window fills, so the client would see nothing.
func TestCompressJSONDoesNotTouchEventStream(t *testing.T) {
	h := CompressJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event: entry-change\ndata: {}\n\n")
		w.(http.Flusher).Flush()
	}))

	req := httptest.NewRequest(http.MethodGet, "/events/entries", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("event stream was encoded as %q", got)
	}
	if !rec.Flushed {
		t.Fatal("flush did not reach the underlying writer")
	}
	if rec.Body.String() != "event: entry-change\ndata: {}\n\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

// The SPA file server compresses its own output. A response that already
// carries a Content-Encoding must not be encoded twice.
func TestCompressJSONDoesNotDoubleEncode(t *testing.T) {
	h := CompressJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "already-encoded")
	}))
	req := httptest.NewRequest(http.MethodGet, "/manifest.json", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Body.String() != "already-encoded" {
		t.Fatalf("pre-encoded body was rewritten: %q", rec.Body.String())
	}
}
