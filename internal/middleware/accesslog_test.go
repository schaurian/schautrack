package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureLogs redirects slog to a buffer for the duration of fn and returns the
// decoded JSON records that were emitted.
func captureLogs(t *testing.T, fn func()) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	fn()

	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad log line %q: %v", line, err)
		}
		recs = append(recs, m)
	}
	return recs
}

func TestAccessLogRecordsStatusAndLevel(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		wantLevel string
	}{
		{"ok", http.StatusOK, "INFO"},
		{"client error", http.StatusBadRequest, "WARN"},
		{"server error", http.StatusInternalServerError, "ERROR"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := AccessLog(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				_, _ = w.Write([]byte("hi"))
			}))

			var recs []map[string]any
			captureFn := func() {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/entries", nil)
				h.ServeHTTP(rec, req)
			}
			recs = captureLogs(t, captureFn)

			if len(recs) != 1 {
				t.Fatalf("want 1 log record, got %d", len(recs))
			}
			m := recs[0]
			if m["level"] != c.wantLevel {
				t.Errorf("level = %v, want %v", m["level"], c.wantLevel)
			}
			if got := int(m["status"].(float64)); got != c.status {
				t.Errorf("status = %d, want %d", got, c.status)
			}
			if got := int(m["bytes"].(float64)); got != 2 {
				t.Errorf("bytes = %d, want 2", got)
			}
			if m["method"] != http.MethodGet || m["path"] != "/entries" {
				t.Errorf("method/path = %v %v, want GET /entries", m["method"], m["path"])
			}
		})
	}
}

func TestAccessLogSkipsHealth(t *testing.T) {
	h := AccessLog(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	recs := captureLogs(t, func() {
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/health", nil))
	})
	if len(recs) != 0 {
		t.Fatalf("health probe should not be logged, got %d records", len(recs))
	}
}

// flushRecorder is an httptest.ResponseRecorder that also reports whether Flush
// was called, so we can assert the wrapper forwards flushes (required for SSE).
type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flushRecorder) Flush() { f.flushed = true }

func TestAccessLogWriterPreservesFlushAndUnwrap(t *testing.T) {
	fr := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}
	var seenFlusher, seenUnwrap bool

	h := AccessLog(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f, ok := w.(http.Flusher); ok {
			seenFlusher = true
			f.Flush()
		}
		type unwrapper interface{ Unwrap() http.ResponseWriter }
		if u, ok := w.(unwrapper); ok {
			seenUnwrap = true
			if u.Unwrap() != fr {
				t.Errorf("Unwrap did not return the underlying writer")
			}
		}
	}))

	captureLogs(t, func() {
		h.ServeHTTP(fr, httptest.NewRequest(http.MethodGet, "/events/entries", nil))
	})

	if !seenFlusher {
		t.Error("wrapper does not expose http.Flusher — SSE would break")
	}
	if !seenUnwrap {
		t.Error("wrapper does not expose Unwrap — http.NewResponseController would break")
	}
	if !fr.flushed {
		t.Error("Flush was not forwarded to the underlying writer")
	}
}
