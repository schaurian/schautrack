package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"schautrack/internal/clientip"
)

// AccessLog emits one structured slog record per HTTP request with the method,
// path, status, byte count, latency and client IP. It gives operators the
// request rates, latencies and error counts the deployment otherwise exposes
// nowhere (there is no metrics/pprof endpoint), so problems like SSE kills or
// rate-limit abuse can be diagnosed from the pod logs.
//
// It is meant to sit at the very top of the chi middleware chain so it observes
// the final committed status, including responses written by the Recovery
// middleware. The response wrapper is deliberately transparent: it forwards
// Flush and exposes Unwrap so long-lived SSE streams and
// http.NewResponseController (used by the SSE handler to clear its write
// deadline) keep working.
//
// The path is logged without its query string on purpose: query strings carry
// OIDC authorization codes and other short-lived secrets that must not land in
// logs. The health endpoint is skipped so Kubernetes liveness/readiness probes
// do not drown the access log.
func AccessLog(trustProxy bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/health" {
				next.ServeHTTP(w, r)
				return
			}

			start := time.Now()
			lw := &accessLogWriter{ResponseWriter: w}
			next.ServeHTTP(lw, r)

			status := lw.status
			if status == 0 {
				// Handler flushed/closed without an explicit WriteHeader or
				// Write (e.g. a hijacked or immediately-closed connection).
				status = http.StatusOK
			}

			attrs := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"status", status,
				"bytes", lw.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
				"ip", clientip.FromRequest(r, trustProxy),
			}

			switch {
			case status >= 500:
				slog.Error("http request", attrs...)
			case status >= 400:
				slog.Warn("http request", attrs...)
			default:
				slog.Info("http request", attrs...)
			}
		})
	}
}

// accessLogWriter records the response status and byte count while forwarding
// everything else to the wrapped ResponseWriter. It implements Flush and Unwrap
// so it stays invisible to SSE flushing and http.NewResponseController.
type accessLogWriter struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (w *accessLogWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *accessLogWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// Flush forwards to the underlying Flusher so SSE streams keep working.
func (w *accessLogWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		if !w.wroteHeader {
			w.status = http.StatusOK
			w.wroteHeader = true
		}
		f.Flush()
	}
}

// Unwrap lets http.NewResponseController reach the underlying writer (the SSE
// handler uses it to clear the per-response write deadline).
func (w *accessLogWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
