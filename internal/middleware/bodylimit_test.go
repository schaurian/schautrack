package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// readBodyHandler drains the request body and records what happened, so a test
// can distinguish "the cap fired" from "the handler read a truncated body and
// carried on regardless" — the second is the dangerous outcome, because a
// handler that ignores the error parses half a JSON document.
func readBodyHandler(read *int, gotErr *error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		*read = len(b)
		*gotErr = err
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func TestMaxBodySizeAllowsBodyUnderLimit(t *testing.T) {
	const limit = 1024
	body := bytes.Repeat([]byte("a"), limit-1)

	var read int
	var readErr error
	req := httptest.NewRequest(http.MethodPost, "/entries", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	MaxBodySize(limit)(readBodyHandler(&read, &readErr)).ServeHTTP(rec, req)

	if readErr != nil {
		t.Fatalf("reading a body under the limit failed: %v", readErr)
	}
	if read != len(body) {
		t.Errorf("handler read %d bytes, want %d — the body was truncated below the limit", read, len(body))
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestMaxBodySizeAllowsBodyExactlyAtLimit pins the boundary. MaxBytesReader
// permits exactly n bytes and errors on the (n+1)th, so a payload of exactly
// the limit must pass.
func TestMaxBodySizeAllowsBodyExactlyAtLimit(t *testing.T) {
	const limit = 1024
	var read int
	var readErr error
	req := httptest.NewRequest(http.MethodPost, "/entries", bytes.NewReader(bytes.Repeat([]byte("a"), limit)))
	rec := httptest.NewRecorder()
	MaxBodySize(limit)(readBodyHandler(&read, &readErr)).ServeHTTP(rec, req)

	if readErr != nil {
		t.Fatalf("a body of exactly the limit was rejected: %v", readErr)
	}
	if read != limit {
		t.Errorf("handler read %d bytes, want %d", read, limit)
	}
}

func TestMaxBodySizeRejectsBodyOverLimit(t *testing.T) {
	const limit = 1024
	var read int
	var readErr error
	req := httptest.NewRequest(http.MethodPost, "/entries", bytes.NewReader(bytes.Repeat([]byte("a"), limit*4)))
	rec := httptest.NewRecorder()
	MaxBodySize(limit)(readBodyHandler(&read, &readErr)).ServeHTTP(rec, req)

	var maxErr *http.MaxBytesError
	if !errors.As(readErr, &maxErr) {
		t.Fatalf("reading an oversized body returned %v, want *http.MaxBytesError — "+
			"without that error the handler cannot tell a truncated body from a complete one", readErr)
	}
	if maxErr.Limit != limit {
		t.Errorf("MaxBytesError.Limit = %d, want %d", maxErr.Limit, limit)
	}
	if read > limit {
		t.Errorf("handler read %d bytes past a %d-byte cap", read, limit)
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", rec.Code)
	}
}

// TestMaxBodySizeIgnoresLyingContentLength is the reason the cap is worth
// having at all. A hostile client can claim any Content-Length it likes;
// MaxBytesReader counts the bytes actually read off the wire, so the header is
// irrelevant to the limit.
func TestMaxBodySizeIgnoresLyingContentLength(t *testing.T) {
	const limit = 1024
	body := bytes.Repeat([]byte("a"), limit*4)

	var read int
	var readErr error
	req := httptest.NewRequest(http.MethodPost, "/entries", bytes.NewReader(body))
	// Claim a tiny body while sending a large one.
	req.ContentLength = 10
	req.Header.Set("Content-Length", "10")

	rec := httptest.NewRecorder()
	MaxBodySize(limit)(readBodyHandler(&read, &readErr)).ServeHTTP(rec, req)

	var maxErr *http.MaxBytesError
	if !errors.As(readErr, &maxErr) {
		t.Fatalf("a request lying about Content-Length was not capped: err = %v, bytes read = %d", readErr, read)
	}
	if read > limit {
		t.Errorf("read %d bytes despite a %d-byte cap", read, limit)
	}
}

// TestMaxBodySizeChunkedWithNoContentLength covers the other half of the same
// point: a chunked upload announces no length at all, and must still be capped.
func TestMaxBodySizeChunkedWithNoContentLength(t *testing.T) {
	const limit = 1024
	var read int
	var readErr error
	req := httptest.NewRequest(http.MethodPost, "/entries", bytes.NewReader(bytes.Repeat([]byte("a"), limit*4)))
	req.ContentLength = -1 // what net/http sets for a chunked request
	req.Header.Del("Content-Length")
	req.TransferEncoding = []string{"chunked"}

	rec := httptest.NewRecorder()
	MaxBodySize(limit)(readBodyHandler(&read, &readErr)).ServeHTTP(rec, req)

	var maxErr *http.MaxBytesError
	if !errors.As(readErr, &maxErr) {
		t.Fatalf("a chunked request with no Content-Length was not capped: err = %v, bytes read = %d", readErr, read)
	}
}

func TestMaxBodySizeHandlesBodylessRequest(t *testing.T) {
	var read int
	var readErr error
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	rec := httptest.NewRecorder()
	MaxBodySize(15<<20)(readBodyHandler(&read, &readErr)).ServeHTTP(rec, req)

	if readErr != nil {
		t.Errorf("a GET with no body errored: %v", readErr)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestMaxBodySizeAllowsFiveMBUnderTheGlobalCap is the control for the v1 limit
// test in v1_bodylimit_test.go. 5 MB sits between the two caps this app has:
// the global 15 MB one lets it through, and the 1 MB one inside decodeV1 must
// not. This half of the contrast needs no database.
func TestMaxBodySizeAllowsFiveMBUnderTheGlobalCap(t *testing.T) {
	var read int
	var readErr error
	req := httptest.NewRequest(http.MethodPost, "/settings/import",
		bytes.NewReader(bytes.Repeat([]byte("a"), 5<<20)))
	rec := httptest.NewRecorder()
	MaxBodySize(15<<20)(readBodyHandler(&read, &readErr)).ServeHTTP(rec, req)

	if readErr != nil {
		t.Fatalf("a 5 MB body was rejected by the 15 MB global cap: %v", readErr)
	}
	if read != 5<<20 {
		t.Errorf("read %d bytes, want %d", read, 5<<20)
	}
}

// TestMaxBodySizeOverRealConnection exercises the cap through an actual TCP
// connection rather than httptest.NewRecorder.
//
// The recorder cannot show the failure mode that matters operationally: whether
// an oversized upload ends in a clean status the client can read, or in a hung
// connection / reset that surfaces as an inscrutable network error. net/http's
// MaxBytesReader marks the request "too large" on the real ResponseWriter and
// closes the connection after the response, so the client must still receive
// the 413 before the close.
func TestMaxBodySizeOverRealConnection(t *testing.T) {
	const limit = 64 << 10

	var read int
	var readErr error
	srv := httptest.NewServer(MaxBodySize(limit)(readBodyHandler(&read, &readErr)))
	defer srv.Close()

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(srv.URL+"/entries", "application/json",
		bytes.NewReader(bytes.Repeat([]byte("a"), limit*8)))
	if err != nil {
		t.Fatalf("the oversized POST produced a transport error instead of an HTTP response: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Errorf("status = %d, want a 4xx — an oversized body is a client error, not a server fault", resp.StatusCode)
	}
	if read > limit {
		t.Errorf("server read %d bytes off the wire despite a %d-byte cap", read, limit)
	}
}

// TestMaxBodySizePassesThroughOtherRequestState checks the middleware only
// swaps the body and leaves the rest of the request alone.
func TestMaxBodySizePassesThroughOtherRequestState(t *testing.T) {
	var gotMethod, gotPath, gotHeader string
	h := MaxBodySize(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotHeader = r.Method, r.URL.Path, r.Header.Get("X-Probe")
	}))

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/entries/7", strings.NewReader("{}"))
	req.Header.Set("X-Probe", "kept")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if gotMethod != http.MethodPatch || gotPath != "/api/v1/entries/7" || gotHeader != "kept" {
		t.Errorf("request mutated: method=%q path=%q X-Probe=%q", gotMethod, gotPath, gotHeader)
	}
}

// TestGlobalBodyLimitIsMountedAt15MB pins the number in cmd/server/main.go.
//
// The middleware is generic; the deployed limit is a literal at the mount site,
// and nothing else in the tree would notice if it were widened. 15 MB is sized
// for photo uploads and account imports on the legacy surface — see the
// maxV1Body comment in internal/handler/v1_common.go for why /api/v1 is tighter.
func TestGlobalBodyLimitIsMountedAt15MB(t *testing.T) {
	src, err := os.ReadFile("../../cmd/server/main.go")
	if err != nil {
		t.Fatalf("reading the router source failed: %v", err)
	}
	const want = "middleware.MaxBodySize(15 << 20)"
	if !strings.Contains(string(src), want) {
		t.Errorf("cmd/server/main.go no longer mounts %s. If the global request cap was changed on "+
			"purpose, update this test in the same commit so the new number is reviewed.", want)
	}
}
