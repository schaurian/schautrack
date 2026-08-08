package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"schautrack/internal/apierr"
)

// captureLog redirects the standard logger (which Recovery uses) into a buffer
// for the duration of a test, both to keep panic stacks out of the test output
// and so a test can assert what was logged.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevWriter, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})
	return &buf
}

func panicking(v any) http.HandlerFunc {
	return func(http.ResponseWriter, *http.Request) { panic(v) }
}

// v1Router mirrors the real composition in cmd/server/main.go and
// handler.MountAPIV1: the legacy Recovery wraps everything, and the /api/v1
// sub-router mounts ProblemRecovery of its own. Rebuilt here rather than
// imported because internal/handler imports this package.
func v1Router(next http.Handler) http.Handler {
	v1 := chi.NewRouter()
	v1.Use(ProblemRecovery)
	v1.Handle("/entries", next)
	v1.Handle("/weight/{date}", next)

	r := chi.NewRouter()
	r.Use(Recovery)
	r.Mount("/api/v1", v1)
	r.Handle("/settings", next)
	r.Handle("/api/entries", next)
	return r
}

// TestRecoveryReturnsLegacyShapeOnSPARoutes pins the SPA contract. The fix for
// the v1 surface must not change what the session/SPA surface answers, because
// the client parses {"ok": false, "error": ...} everywhere else.
func TestRecoveryReturnsLegacyShapeOnSPARoutes(t *testing.T) {
	captureLog(t)

	h := v1Router(panicking("kaboom"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/entries", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (body: %q)", err, w.Body.String())
	}
	if body["ok"] != false {
		t.Errorf(`body["ok"] = %v, want false`, body["ok"])
	}
	if body["error"] != "Internal server error" {
		t.Errorf(`body["error"] = %v, want "Internal server error"`, body["error"])
	}
}

// TestRecoveryReturnsProblemJSONOnV1Routes is the regression test for #307: a
// panic under /api/v1 used to fall through to the global Recovery and answer in
// the legacy envelope, violating v1 invariant #3. Every v1 error — including
// the ones no handler chose to return — must be an RFC 9457 problem.
func TestRecoveryReturnsProblemJSONOnV1Routes(t *testing.T) {
	captureLog(t)

	h := v1Router(panicking("kaboom"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != apierr.ContentType {
		t.Fatalf("Content-Type = %q, want %q — a panic on a v1 route must not answer in the legacy shape",
			ct, apierr.ContentType)
	}

	var p apierr.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("body is not JSON: %v (body: %q)", err, w.Body.String())
	}
	if p.Type != "https://schautrack.com/problems/internal-error" {
		t.Errorf("type = %q, want the internal-error problem type", p.Type)
	}
	if p.Title == "" {
		t.Error("title is empty")
	}
	if p.Status != http.StatusInternalServerError {
		t.Errorf("status member = %d, want 500", p.Status)
	}
	if p.Detail == "" {
		t.Error("detail is empty — a client has nothing to show the user")
	}
	if p.Instance != "/api/v1/entries" {
		t.Errorf("instance = %q, want /api/v1/entries", p.Instance)
	}

	// The legacy members must be absent, not merely ignored: a client that
	// sniffs for "ok" would otherwise still see the old shape.
	var raw map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &raw)
	if _, ok := raw["ok"]; ok {
		t.Error(`problem body carries an "ok" member — the legacy envelope leaked through`)
	}
}

// TestRecoveryDoesNotLeakPanicDetail checks that the panic value and the stack
// reach the operator's log and nothing else. A stack frame in a response body
// hands out the server's package and file layout, and a panic value routinely
// carries request data.
func TestRecoveryDoesNotLeakPanicDetail(t *testing.T) {
	const secret = "panic-value-2f8c1a-user@example.com"

	for _, tc := range []struct {
		name string
		path string
	}{
		{"spa", "/settings"},
		{"v1", "/api/v1/weight/2026-01-01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logged := captureLog(t)

			h := v1Router(panicking(secret))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))

			body := w.Body.String()
			if strings.Contains(body, secret) {
				t.Errorf("response body leaks the panic value: %q", body)
			}
			for _, frame := range []string{"goroutine ", "runtime/debug", "recovery.go:", "recovery_test.go:", ".go:"} {
				if strings.Contains(body, frame) {
					t.Errorf("response body leaks a stack frame (%q): %q", frame, body)
				}
			}

			// The other half of the contract: it must actually be logged, or
			// the panic becomes undebuggable.
			if !strings.Contains(logged.String(), secret) {
				t.Error("panic value was not logged")
			}
			if !strings.Contains(logged.String(), "goroutine ") {
				t.Errorf("stack was not logged: %q", logged.String())
			}
		})
	}
}

// TestRecoveryAfterPartialWrite covers a panic raised after the handler has
// already committed a status and part of a body. Recovery used to call WriteHeader
// unconditionally, which logged a "superfluous response.WriteHeader" warning
// and appended a second JSON document to the half-written response — so the
// client got a 200 status line and a body that was two concatenated values.
// Nothing is recoverable at that point: the correct behaviour is to log and
// leave the response truncated.
func TestRecoveryAfterPartialWrite(t *testing.T) {
	partial := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "partial")
		panic("kaboom")
	})

	for _, tc := range []struct {
		name string
		path string
	}{
		{"spa", "/settings"},
		{"v1", "/api/v1/entries"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logged := captureLog(t)

			w := httptest.NewRecorder()
			v1Router(partial).ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))

			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want the 200 the handler already committed", w.Code)
			}
			if got := w.Body.String(); got != "partial" {
				t.Errorf("body = %q, want %q — an error document was appended to a committed response", got, "partial")
			}
			if ct := w.Header().Get("Content-Type"); ct != "text/plain" {
				t.Errorf("Content-Type = %q, want text/plain — the committed header was overwritten", ct)
			}
			if !strings.Contains(logged.String(), "kaboom") {
				t.Errorf("panic after commit was not logged: %q", logged.String())
			}
		})
	}

	// The recorder cannot see a "superfluous response.WriteHeader" warning —
	// only a real net/http server emits that — so check it end to end too.
	t.Run("no superfluous WriteHeader on a real server", func(t *testing.T) {
		captureLog(t)

		var serverLog bytes.Buffer
		srv := httptest.NewUnstartedServer(v1Router(partial))
		srv.Config.ErrorLog = log.New(&serverLog, "", 0)
		srv.Start()

		resp, err := srv.Client().Get(srv.URL + "/api/v1/entries")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		srv.Close() // waits for the handler goroutine, so serverLog is settled

		if string(body) != "partial" {
			t.Errorf("body = %q, want %q", body, "partial")
		}
		if strings.Contains(serverLog.String(), "superfluous") {
			t.Errorf("server logged a superfluous WriteHeader: %q", serverLog.String())
		}
	})
}

// TestRecoveryWriterIsTransparent guards the wrapper Recovery installs to spot
// a committed response. SSE streams flush through it and the SSE handler
// clears its write deadline with http.NewResponseController, which needs
// Unwrap; an opaque wrapper would break long-lived streams.
func TestRecoveryWriterIsTransparent(t *testing.T) {
	var inner http.ResponseWriter
	var flushed bool

	rec := httptest.NewRecorder()
	h := Recovery(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		inner = w
		if _, ok := w.(http.Flusher); !ok {
			t.Error("wrapper does not implement Flusher — SSE streams would stall")
		}
		if u, ok := w.(interface{ Unwrap() http.ResponseWriter }); !ok {
			t.Error("wrapper does not expose Unwrap — http.NewResponseController would break")
		} else if u.Unwrap() != rec {
			t.Error("Unwrap does not return the wrapped writer")
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("ResponseController.Flush: %v", err)
		}
		flushed = true
	}))
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/events", nil))

	if !flushed {
		t.Fatal("handler did not run")
	}
	if inner == rec {
		t.Error("Recovery did not wrap the ResponseWriter, so it cannot detect a committed response")
	}
	if !rec.Flushed {
		t.Error("Flush did not reach the underlying writer")
	}
}
