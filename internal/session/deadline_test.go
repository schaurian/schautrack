package session

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestDeferredSaveWriterUnwrapReachesWriteDeadline guards the SSE fix: the SSE
// handler clears its per-connection write deadline via
// http.NewResponseController(w).SetWriteDeadline(time.Time{}). That only works
// if every ResponseWriter wrapper between the router and the handler exposes
// Unwrap() so the controller can reach the underlying net/http conn. The
// session middleware wraps the writer in deferredSaveWriter, so this test
// asserts that wrapper does not break the Unwrap chain over a real server
// (where the base writer actually supports SetWriteDeadline).
func TestDeferredSaveWriterUnwrapReachesWriteDeadline(t *testing.T) {
	var clearErr error
	cleared := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap exactly as session.Middleware does. saved:true short-circuits
		// saveOnce so the write below doesn't reach the (nil) store — the
		// deadline clear under test does not depend on the session save path.
		rw := &deferredSaveWriter{ResponseWriter: w, saved: true}
		rc := http.NewResponseController(rw)
		clearErr = rc.SetWriteDeadline(time.Time{})
		close(cleared)
		fmt.Fprint(rw, "ok")
		rw.Flush()
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	<-cleared

	if clearErr != nil {
		t.Fatalf("SetWriteDeadline through deferredSaveWriter returned %v (ErrNotSupported=%v); "+
			"the Unwrap chain is broken and SSE streams would be force-closed by WriteTimeout",
			clearErr, clearErr == http.ErrNotSupported)
	}
}
