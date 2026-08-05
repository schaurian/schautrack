// Package apierr implements RFC 9457 "Problem Details for HTTP APIs" — the
// error format of the public /api/v1 surface.
//
// It lives in its own package (rather than in internal/handler) because both
// internal/handler and internal/middleware need to emit problems, and handler
// already imports middleware. Putting Problem in either of those would create
// an import cycle.
//
// The app's own session-authenticated API keeps its legacy
// {"ok": false, "error": "..."} shape — see handler.ErrorJSON. Only /api/v1
// speaks problem+json, so changing one never breaks the other.
package apierr

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// ContentType is the media type mandated by RFC 9457 §3.
const ContentType = "application/problem+json"

// typeBase prefixes every machine-readable problem type. RFC 9457 §3.1.1 wants
// a URI reference that identifies the problem type; these are stable
// identifiers first and documentation anchors second.
const typeBase = "https://schautrack.com/problems/"

// InvalidParam describes a single rejected field. RFC 9457 leaves per-field
// reporting to extension members; "invalid_params" is the convention from the
// RFC's own example (§3.2).
type InvalidParam struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// Problem is an RFC 9457 problem details object.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`

	// Instance identifies the specific occurrence — we set it to the request
	// path so a report ("I got a 422 from /api/v1/entries") is self-locating.
	Instance string `json:"instance,omitempty"`

	InvalidParams []InvalidParam `json:"invalid_params,omitempty"`

	// RequiredScope is set on 403s caused by a token missing a scope, so a
	// client can tell the user exactly which scope to add instead of making
	// them guess from prose.
	RequiredScope string `json:"required_scope,omitempty"`
}

// Error lets a Problem be returned as an error from helper functions.
func (p *Problem) Error() string { return p.Title + ": " + p.Detail }

// New builds a problem. slug becomes the type URI suffix.
func New(status int, slug, title, detail string) *Problem {
	return &Problem{Type: typeBase + slug, Title: title, Status: status, Detail: detail}
}

// Write emits the problem as problem+json. It stamps Instance from the request
// path when the caller has not set one.
func Write(w http.ResponseWriter, r *http.Request, p *Problem) {
	if p.Instance == "" && r != nil {
		p.Instance = r.URL.Path
	}
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(p.Status)
	if err := json.NewEncoder(w).Encode(p); err != nil {
		slog.Error("failed to encode problem response", "error", err)
	}
}

// --- Constructors for the statuses /api/v1 actually returns ----------------
//
// Every problem the API can emit is created through one of these, so the set
// of type URIs is closed and enumerable — the OpenAPI document and the
// generated docs list exactly these and nothing else.

// BadRequest — the request itself is malformed (unparseable JSON, bad query
// parameter). Distinct from Unprocessable, which is well-formed but invalid.
func BadRequest(detail string) *Problem {
	return New(http.StatusBadRequest, "bad-request", "Bad request", detail)
}

// Unauthorized — no credentials, or credentials that are not valid.
func Unauthorized(detail string) *Problem {
	return New(http.StatusUnauthorized, "unauthorized", "Unauthorized", detail)
}

// Forbidden — valid credentials that are not allowed to do this.
func Forbidden(detail string) *Problem {
	return New(http.StatusForbidden, "forbidden", "Forbidden", detail)
}

// InsufficientScope — the token is valid but lacks the required scope. Split
// out from Forbidden so clients can branch on it and re-mint a token.
func InsufficientScope(required string) *Problem {
	p := New(http.StatusForbidden, "insufficient-scope", "Insufficient scope",
		"This token does not carry the scope required for this endpoint.")
	p.RequiredScope = required
	return p
}

// NotFound — the resource does not exist, or belongs to another user. Those
// two cases are deliberately indistinguishable: returning 403 for "exists but
// is someone else's" would leak the existence of other users' record IDs.
func NotFound(detail string) *Problem {
	return New(http.StatusNotFound, "not-found", "Not found", detail)
}

// Conflict — the request collides with existing state (duplicate name).
func Conflict(detail string) *Problem {
	return New(http.StatusConflict, "conflict", "Conflict", detail)
}

// Unprocessable — syntactically fine, semantically rejected. Carries
// invalid_params so a client can highlight the offending fields.
func Unprocessable(detail string, params ...InvalidParam) *Problem {
	p := New(http.StatusUnprocessableEntity, "validation-failed", "Validation failed", detail)
	p.InvalidParams = params
	return p
}

// TooManyRequests — the caller exceeded its rate limit.
func TooManyRequests(detail string) *Problem {
	return New(http.StatusTooManyRequests, "rate-limited", "Too many requests", detail)
}

// Internal — an unexpected server-side failure. detail is deliberately generic
// at the call sites; the real cause goes to the log, not to the client.
func Internal(detail string) *Problem {
	return New(http.StatusInternalServerError, "internal-error", "Internal server error", detail)
}
