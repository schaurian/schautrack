package middleware

import (
	"encoding/json"
	"fmt"
	"log/slog"
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
//
// http.ErrAbortHandler is the one panic value it does not recover: a handler
// panicking with it is deliberately abandoning the response, so it propagates
// to net/http, which closes the connection and logs nothing. Recovered panics
// are logged as a single structured slog record ("panic recovered").
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
//
// http.ErrAbortHandler is deliberately not recovered — see the re-panic below.
func recoverWith(next http.Handler, write func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &recoveryWriter{ResponseWriter: w}
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}

			// http.ErrAbortHandler is not a failure: it is the sentinel a
			// handler panics with to say "abandon this response and close the
			// connection, quietly". net/http special-cases it in conn.serve,
			// so re-panicking gets exactly that behaviour. Recovering it
			// instead would write a 500 onto a response the handler asked to
			// be abandoned — into a writer whose framing may already be gone
			// if the stream was half-sent or the connection hijacked — and log
			// a stack trace for something that is by definition not a bug.
			//
			// It must be handled here in the shared body rather than in
			// Recovery/ProblemRecovery: on a v1 route the inner
			// ProblemRecovery runs first, so if only one layer re-panicked the
			// other would still catch the sentinel.
			//
			// Nothing is logged, on purpose. An intentional abort is not an
			// error, and a scary "panic recovered" record for one would train
			// operators to ignore the alert that matters. AccessLog sits above
			// this middleware and does not recover, so an aborted request also
			// gets no access-log line — accepted: an abandoned response has no
			// meaningful status to report. Same precedent as chi's Recoverer.
			if rec == http.ErrAbortHandler {
				panic(rec)
			}

			// This was log.Printf. main.go calls slog.SetDefault, which
			// reroutes the log package through the same JSON handler, so the
			// old call did reach stdout — but as a record at INFO (the level
			// slog hardcodes for log package output) whose msg was the panic
			// plus the entire stack. A panic therefore sat below the error
			// threshold, carried no request context, and had a msg unique to
			// each occurrence, which no alert rule can match and no two
			// occurrences can be grouped by. Hence ERROR, a fixed msg, and the
			// stack as its own attribute. The msg is the same on both branches
			// so one rule catches every panic; response_committed marks the
			// unsalvageable case.
			//
			// The panic value and the stack stop at the operator's log. Both
			// routinely carry request data, and a stack frame hands out the
			// server's package and file layout; the client gets the fixed,
			// generic body write produces instead. The path is logged without
			// its query string for the same reason AccessLog does so: query
			// strings carry OIDC codes and other short-lived secrets.
			slog.Error("panic recovered",
				"panic", fmt.Sprint(rec),
				"method", r.Method,
				"path", r.URL.Path,
				"response_committed", rw.committed,
				"stack", string(debug.Stack()),
			)

			if rw.committed {
				// The handler already wrote a status and probably part of a
				// body. Writing the error document now would append a second
				// JSON value to a half-written response and provoke a
				// "superfluous response.WriteHeader" warning, while the status
				// line — already on the wire — would still claim success.
				// Nothing can be salvaged: leave the response truncated so the
				// framing, not a bogus body, tells the client it is incomplete.
				return
			}

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
