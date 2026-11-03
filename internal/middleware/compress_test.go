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
	// Larger than the minimum size, so only the content-type gate can be what
	// keeps it plain.
	event := "event: entry-change\ndata: {\"pad\":\"" + strings.Repeat("z", 2*compressMinSize) + "\"}\n\n"
	h := CompressJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, event)
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
	if rec.Body.String() != event {
		t.Fatalf("event stream body was rewritten (%d bytes)", rec.Body.Len())
	}
}

// serveWith runs body through CompressJSON as contentType, for a client that
// accepts gzip, and returns the recorded response.
func serveWith(t *testing.T, contentType, body string, extra http.Header) *httptest.ResponseRecorder {
	t.Helper()
	h := CompressJSON(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		for k, v := range extra {
			w.Header()[k] = v
		}
		_, _ = io.WriteString(w, body)
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The SPA file server compresses its own output. A response that already
// carries a Content-Encoding must not be encoded twice.
func TestCompressJSONDoesNotDoubleEncode(t *testing.T) {
	body := strings.Repeat("already-encoded ", 200)
	rec := serveWith(t, "application/json", body, http.Header{"Content-Encoding": {"gzip"}})
	if rec.Body.String() != body {
		t.Fatalf("pre-encoded body was rewritten (%d bytes)", rec.Body.Len())
	}
}

// Below the minimum, gzip's framing costs more than it saves: a small JSON
// answer must go out as it is.
func TestCompressJSONSkipsSmallBodies(t *testing.T) {
	body := `{"ok":true,"todos":[]}`
	rec := serveWith(t, "application/json", body, nil)
	if got := rec.Header().Get("Content-Encoding"); got != "" {
		t.Fatalf("a %d-byte body was encoded as %q", len(body), got)
	}
	if rec.Body.String() != body {
		t.Fatalf("body = %q", rec.Body.String())
	}

	// The threshold, not "never": one past it is encoded.
	big := `{"pad":"` + strings.Repeat("x", compressMinSize) + `"}`
	if got := serveWith(t, "application/json", big, nil).Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("a %d-byte body was not gzip'd (Content-Encoding %q)", len(big), got)
	}
}

// The v1 API's own JSON types are JSON too.
func TestCompressJSONCoversStructuredJSONTypes(t *testing.T) {
	body := `{"pad":"` + strings.Repeat("q", 2*compressMinSize) + `"}`
	for _, ct := range []string{"application/json; charset=utf-8", "application/problem+json", "application/openapi+json;version=3.1"} {
		if got := serveWith(t, ct, body, nil).Header().Get("Content-Encoding"); got != "gzip" {
			t.Errorf("%s: Content-Encoding = %q, want gzip", ct, got)
		}
	}
}

// JSON only. HTML, CSS and JavaScript reach this wrapper from the SPA file
// server, which has its own compressor; this one must leave them alone.
func TestCompressJSONLeavesOtherContentTypesAlone(t *testing.T) {
	for _, ct := range []string{"text/html; charset=utf-8", "text/css; charset=utf-8", "text/javascript; charset=utf-8", "image/svg+xml", "text/plain; charset=utf-8", "application/xml", "text/json-ish"} {
		body := strings.Repeat("<p>not json</p>\n", 400)
		rec := serveWith(t, ct, body, nil)
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Errorf("%s was encoded as %q", ct, got)
		}
		if rec.Body.String() != body {
			t.Errorf("%s body was rewritten", ct)
		}
	}
}

// Only gzip is offered, the encoding the rest of the app uses, even to a
// client that would take zstd.
func TestCompressJSONUsesGzipOnly(t *testing.T) {
	body := `{"pad":"` + strings.Repeat("y", 4*compressMinSize) + `"}`
	if got := serveWith(t, "application/json", body, nil).Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
}
