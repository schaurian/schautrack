package handler

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"schautrack/internal/apierr"
)

// TestV1RouterRecoversAsProblemJSON pins the mount, not just the middleware:
// middleware.ProblemRecovery only protects v1 if MountAPIV1 actually installs
// it. Drop the r.Use and a panic falls through to the globally-mounted
// middleware.Recovery, which answers in the legacy {"ok": false} envelope and
// breaks v1 invariant #3 (see #307).
//
// The probe route is registered on the router MountAPIV1 returns, so it rides
// the real middleware chain. It is added after construction and never appears
// in another test's instance, so TestV1RoutesMatchSpec is unaffected.
func TestV1RouterRecoversAsProblemJSON(t *testing.T) {
	prevWriter, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prevWriter); log.SetFlags(prevFlags) })

	router := (&V1Handler{}).MountAPIV1(nil)
	router.Get("/panic-probe", func(http.ResponseWriter, *http.Request) {
		panic("kaboom")
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/panic-probe", nil))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != apierr.ContentType {
		t.Fatalf("Content-Type = %q, want %q — MountAPIV1 is not recovering panics as problem details",
			ct, apierr.ContentType)
	}

	var p apierr.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("body is not JSON: %v (body: %q)", err, w.Body.String())
	}
	if p.Status != http.StatusInternalServerError || p.Title == "" || p.Detail == "" {
		t.Errorf("problem = %+v, want a populated 500 problem", p)
	}
}
