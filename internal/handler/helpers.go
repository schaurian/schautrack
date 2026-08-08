package handler

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

// JSON writes a JSON response with the given status code.
func JSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}

// ReadJSON decodes a JSON request body into dst, limited to 10MB.
func ReadJSON(r *http.Request, dst any) error {
	return ReadJSONLimit(nil, r, dst, 10<<20)
}

// ReadJSONLimit decodes a JSON request body into dst, rejecting bodies larger
// than limit bytes. Oversize bodies surface as a *http.MaxBytesError (instead
// of being silently truncated) so callers can map them to 413. w may be nil;
// when non-nil, the server also stops reading the connection on overflow.
func ReadJSONLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}

// ReadOptionalJSON decodes a request body that the caller is allowed to omit.
//
// It exists because several handlers take a body whose fields are all optional
// and were therefore calling ReadJSON and dropping the error entirely. That
// conflates two very different situations: "no body was sent", which is
// legitimate and must leave dst at its zero value, and "a body was sent and it
// is malformed", which is a client bug that was being answered with a 200 and
// the zero value. POST /api/todos/toggle-enabled with a broken body silently
// DISABLED the user's todos, because the decode failure left Enabled nil and
// nil is not true.
//
// An absent or whitespace-only body is not an error. Anything else must parse.
func ReadOptionalJSON(r *http.Request, dst any) error {
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 10<<20))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return json.Unmarshal(body, dst)
}

// ErrorJSON writes a JSON error response.
func ErrorJSON(w http.ResponseWriter, status int, message string) {
	JSON(w, status, map[string]any{"ok": false, "error": message})
}

// OkJSON writes a JSON success response.
func OkJSON(w http.ResponseWriter, extra ...map[string]any) {
	result := map[string]any{"ok": true}
	for _, m := range extra {
		for k, v := range m {
			result[k] = v
		}
	}
	JSON(w, http.StatusOK, result)
}
