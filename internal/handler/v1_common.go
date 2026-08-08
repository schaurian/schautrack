package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"schautrack/internal/apierr"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/service"
)

// --- Response shapes ------------------------------------------------------

// v1List is the envelope for every collection endpoint.
//
// Collections are wrapped and single resources are not. The wrapper exists so
// pagination metadata has somewhere to live and so a collection can grow one
// later without a breaking change; a single resource has no such need, and
// wrapping it would only add a level of indirection to every client.
type v1List[T any] struct {
	Data []T `json:"data"`

	// HasMore and NextCursor are present on paginated collections only.
	HasMore    *bool   `json:"has_more,omitempty"`
	NextCursor *string `json:"next_cursor,omitempty"`
}

// writeV1 emits a JSON response. Unlike the legacy JSON helper it writes no
// {"ok": true} envelope: on the v1 surface the status code carries that.
func writeV1(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("failed to encode v1 response", "error", err)
	}
}

// noContent completes a successful mutation that has nothing to return.
func noContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// --- Optional: absent vs. null vs. present --------------------------------

// Optional distinguishes the three states a field can be in inside a PATCH
// body: absent (leave alone), explicitly null (clear it), or present with a
// value (set it).
//
// A `**T` field does NOT achieve this, despite looking like it should:
// encoding/json unmarshals an explicit `null` into a pointer by setting that
// pointer to nil, which is byte-for-byte the same result as the key being
// absent. So `{"protein_g": null}` and `{}` become indistinguishable and
// "clear this macro" silently turns into "change nothing".
//
// Implementing json.Unmarshaler fixes it, because encoding/json calls
// UnmarshalJSON for an explicit null (passing the literal bytes "null") and
// does not call it at all when the key is missing. Set is therefore true only
// in the two present cases.
type Optional[T any] struct {
	// Set reports whether the key appeared in the body at all.
	Set bool
	// Value is nil when the key appeared with a null value.
	Value *T
}

func (o *Optional[T]) UnmarshalJSON(data []byte) error {
	o.Set = true
	if string(data) == "null" {
		o.Value = nil
		return nil
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	o.Value = &v
	return nil
}

// MarshalJSON is provided for completeness so a struct carrying Optional
// fields can round-trip in tests.
func (o Optional[T]) MarshalJSON() ([]byte, error) {
	if !o.Set || o.Value == nil {
		return []byte("null"), nil
	}
	return json.Marshal(*o.Value)
}

// --- Request parsing ------------------------------------------------------

// maxV1Body caps a v1 request body at 1 MB. The global limit is 15 MB to allow
// photo uploads and account imports on the legacy surface; nothing in v1 takes
// a payload remotely that size, so it gets a tighter bound of its own.
const maxV1Body = 1 << 20

// decodeV1 reads a JSON body into dst, requiring it to be a single JSON object
// and rejecting unknown fields.
//
// DisallowUnknownFields is the deliberate choice here. A public API that
// silently ignores `{"calorie": 500}` (note the typo) hands the caller a
// success response and drops their data. Failing with a message naming the
// unknown field turns a silent data-loss bug into an obvious 400.
//
// It decodes in two passes, which looks redundant and is not. Decoding the
// body straight into dst cannot distinguish a bare `null` from `{}`:
// encoding/json treats a top-level null literal as "leave the destination
// alone", so Decode returns no error, dst stays zero-valued, and the handler
// runs as though the caller had sent an empty object. On the PUT-replace
// endpoints a zero-valued struct is a destructive instruction — `Content: ""`
// on PUT /notes/{date} means "delete this note" — so a body carrying no
// instruction at all deleted a note and returned 200. That is the same silent
// data loss DisallowUnknownFields exists to prevent, so a top-level value that
// is not an object is refused before dst is ever touched.
func decodeV1(w http.ResponseWriter, r *http.Request, dst any) *apierr.Problem {
	if r.Body == nil {
		return apierr.BadRequest("A JSON request body is required.")
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxV1Body))

	// Pass 1 reads the body as an uninterpreted value. This is where the size
	// limit and JSON syntax are enforced — both have to win over the shape
	// check below, because a body that cannot be read has no shape to report.
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return decodeV1Problem(err)
	}

	// Decode strips leading whitespace, so raw starts at the value itself. An
	// array, string, number, boolean or null gets the same 400 as the
	// multi-value case below: the caller sent something that is not a request
	// body for this endpoint, and saying which shape was expected is the only
	// actionable thing to tell them.
	if len(raw) == 0 || raw[0] != '{' {
		return apierr.BadRequest("The request body must be a JSON object.")
	}

	// Pass 2 fills dst from the object. It runs over the bytes pass 1 already
	// read, so the body is never read twice.
	obj := json.NewDecoder(bytes.NewReader(raw))
	obj.DisallowUnknownFields()
	if err := obj.Decode(dst); err != nil {
		return decodeV1Problem(err)
	}

	// A second Decode on the *body* must hit EOF; anything else means the
	// caller sent more than one JSON value and half of it would be ignored.
	// Checked last so that a malformed first object is reported as the field
	// error it is rather than as a multi-value body.
	if dec.More() {
		return apierr.BadRequest("The request body must contain exactly one JSON object.")
	}
	return nil
}

// decodeV1Problem maps an encoding/json failure onto a problem detail. Shared
// by both decodeV1 passes: the size and syntax errors can only come from the
// first, the field-level ones only from the second, and keeping one mapping
// means the two passes cannot drift into reporting the same fault differently.
func decodeV1Problem(err error) *apierr.Problem {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return apierr.New(http.StatusRequestEntityTooLarge, "body-too-large",
			"Request body too large",
			fmt.Sprintf("The request body exceeds the %d byte limit.", maxV1Body))
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		// Field is empty when the mismatch is the body itself rather than one
		// of its fields. decodeV1's own shape check now catches that case
		// first, so this branch is a backstop for a dst that is not a struct;
		// it stays because typeErr.Type is the destination *Go* type, and
		// answering `{"name": "", "reason": "expected handler.v1EntryInput"}`
		// is both useless to the caller and a leak of an internal type name
		// into a public response.
		if typeErr.Field == "" {
			return apierr.BadRequest("The request body must be a JSON object.")
		}
		return apierr.Unprocessable("A field has the wrong type.",
			apierr.InvalidParam{
				Name:   typeErr.Field,
				Reason: fmt.Sprintf("expected %s", typeErr.Type.String()),
			})
	}
	// json's unknown-field error is only available as a string; converting it
	// here is what lets the caller see WHICH field they misspelled.
	if field, ok := strings.CutPrefix(err.Error(), "json: unknown field "); ok {
		return apierr.BadRequest("Unknown field " + field + ".")
	}
	return apierr.BadRequest("The request body is not valid JSON.")
}

// pathDate reads and validates a YYYY-MM-DD path parameter.
func pathDate(r *http.Request) (string, *apierr.Problem) {
	d := chi.URLParam(r, "date")
	if !isValidDate(d) {
		return "", apierr.BadRequest("The date must be in YYYY-MM-DD format.")
	}
	return d, nil
}

// pathID reads and validates a positive integer path parameter.
func pathID(r *http.Request) (int, *apierr.Problem) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil || id <= 0 {
		return 0, apierr.BadRequest("The id must be a positive integer.")
	}
	return id, nil
}

// queryDate reads an optional YYYY-MM-DD query parameter. A missing parameter
// yields ("", nil); a present-but-malformed one is an error rather than being
// silently ignored.
func queryDate(r *http.Request, name string) (string, *apierr.Problem) {
	v := strings.TrimSpace(r.URL.Query().Get(name))
	if v == "" {
		return "", nil
	}
	if !isValidDate(v) {
		return "", apierr.BadRequest(fmt.Sprintf("%q must be in YYYY-MM-DD format.", name))
	}
	return v, nil
}

const (
	defaultPageSize = 50
	maxPageSize     = 200
)

// queryLimit reads the page size, clamped to maxPageSize.
func queryLimit(r *http.Request) (int, *apierr.Problem) {
	v := strings.TrimSpace(r.URL.Query().Get("limit"))
	if v == "" {
		return defaultPageSize, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, apierr.BadRequest(`"limit" must be a positive integer.`)
	}
	if n > maxPageSize {
		n = maxPageSize
	}
	return n, nil
}

// --- Keyset pagination ----------------------------------------------------
//
// Entries paginate by keyset, not by OFFSET. Entries are ordered newest-first
// and new ones are inserted constantly, so an OFFSET-based page 2 would skip
// or repeat rows whenever a row is added between requests. A cursor pinned to
// the last row of the previous page cannot slip like that.

// cursor is the opaque position token: the (date, id) of the last row of the
// previous page. It is base64 solely to discourage clients from parsing and
// depending on the format.
type cursor struct {
	Date string
	ID   int
}

func encodeCursor(c cursor) string {
	return base64.RawURLEncoding.EncodeToString([]byte(c.Date + "," + strconv.Itoa(c.ID)))
}

func decodeCursor(s string) (cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return cursor{}, errors.New("malformed cursor")
	}
	date, idStr, ok := strings.Cut(string(raw), ",")
	if !ok || !isValidDate(date) {
		return cursor{}, errors.New("malformed cursor")
	}
	id, err := strconv.Atoi(idStr)
	if err != nil || id <= 0 {
		return cursor{}, errors.New("malformed cursor")
	}
	return cursor{Date: date, ID: id}, nil
}

// queryCursor reads the optional pagination cursor.
func queryCursor(r *http.Request) (*cursor, *apierr.Problem) {
	v := strings.TrimSpace(r.URL.Query().Get("cursor"))
	if v == "" {
		return nil, nil
	}
	c, err := decodeCursor(v)
	if err != nil {
		return nil, apierr.BadRequest("The cursor is malformed. Use the next_cursor value from a previous response verbatim.")
	}
	return &c, nil
}

// --- Shared context helpers ----------------------------------------------

// v1User returns the authenticated user. RequireAPIToken guarantees one is
// present on every routed v1 request.
func v1User(r *http.Request) *model.User { return middleware.GetCurrentUser(r) }

// v1Today returns today's date in the user's timezone. A script that POSTs an
// entry with no date means "now, where I am", and the user's stored timezone is
// the only defensible interpretation — a token has no browser to ask.
func v1Today(r *http.Request) string {
	user := v1User(r)
	tz := user.GetTimezone()
	if tz == "" {
		tz = "UTC"
	}
	return service.FormatDateInTz(time.Now(), tz)
}

// v1Tz returns the timezone used to render timestamps for this user.
func v1Tz(r *http.Request) string {
	tz := v1User(r).GetTimezone()
	if tz == "" {
		tz = "UTC"
	}
	return tz
}

// dbFail logs the real error and returns the generic problem sent to clients.
// Every 500 on the v1 surface goes through here so no internal detail — table
// names, constraint names, driver messages — can reach a caller.
func dbFail(op string, err error) *apierr.Problem {
	slog.Error("v1 database operation failed", "op", op, "error", err)
	return apierr.Internal("The request could not be completed.")
}
