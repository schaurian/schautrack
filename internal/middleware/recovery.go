package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"

	"schautrack/internal/apierr"
)

// Recovery catches panics and returns a 500 in the legacy
// {"ok": false, "error": "..."} envelope.
//
// This is the error boundary of the SPA/session surface, and it is mounted
// globally in cmd/server/main.go. The public API must NOT answer in this shape
// — v1 errors are RFC 9457 problem details — so /api/v1 mounts ProblemRecovery
// inside its own router instead. See handler.MountAPIV1.
func Recovery(next http.Handler) http.Handler {
	return recoverWith(next, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":    false,
			"error": "Internal server error",
		})
	})
}

// ProblemRecovery is Recovery with an RFC 9457 rejection, for the public API
// surface — the same split as NewRateLimiter/NewProblemRateLimiter.
//
// It is mounted inside handler.MountAPIV1 rather than switched on r.URL.Path
// from the global Recovery, so the route table stays the one place that decides
// which surface a request belongs to (v1 invariant #2). Because it sits inside
// the v1 mount it recovers first, and the global Recovery above it never sees
// the panic.
func ProblemRecovery(next http.Handler) http.Handler {
	return recoverWith(next, func(w http.ResponseWriter, r *http.Request) {
		apierr.Write(w, r, apierr.Internal("The request could not be completed."))
	})
}

// recoverWith is the shared body of Recovery and ProblemRecovery: catch the
// panic, log it with its stack, and let write render the surface-appropriate
// error document.
func recoverWith(next http.Handler, write func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &recoveryWriter{ResponseWriter: w}
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}

			if rw.committed {
				// The handler already wrote a status and probably part of a
				// body. Writing the error document now would append a second
				// JSON value to a half-written response and provoke a
				// "superfluous response.WriteHeader" warning, while the status
				// line — already on the wire — would still claim success.
				// Nothing can be salvaged: leave the response truncated so the
				// framing, not a bogus body, tells the client it is incomplete.
				log.Printf("panic after response was committed (%s %s), response left truncated: %v\n%s",
					r.Method, r.URL.Path, rec, debug.Stack())
				return
			}

			// The panic value and the stack go to the operator's log and stop
			// there. Both routinely carry request data, and a stack frame hands
			// out the server's package and file layout; the client gets the
			// fixed, generic body write produces instead.
			log.Printf("panic: %v\n%s", rec, debug.Stack())
			write(rw, r)
		}()
		next.ServeHTTP(rw, r)
	})
}

// recoveryWriter records whether the response has been committed, so a panic
// raised after the handler started writing does not double-write.
//
// It mirrors accessLogWriter: deliberately transparent, forwarding Flush and
// exposing Unwrap so SSE streams and http.NewResponseController (the SSE
// handler clears its write deadline through it) keep working.
type recoveryWriter struct {
	http.ResponseWriter
	committed bool
}

func (w *recoveryWriter) WriteHeader(code int) {
	w.committed = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *recoveryWriter) Write(b []byte) (int, error) {
	w.committed = true
	return w.ResponseWriter.Write(b)
}

// Flush forwards to the underlying Flusher so SSE streams keep working. A flush
// commits the response even if nothing was written explicitly.
func (w *recoveryWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		w.committed = true
		f.Flush()
	}
}

// Unwrap lets http.NewResponseController reach the underlying writer.
func (w *recoveryWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
