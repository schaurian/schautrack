package handler

import (
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"schautrack/internal/apierr"
)

// Characterization tests for the v1 request-parsing helpers in v1_common.go.
//
// Every /api/v1 request passes through these eight functions before a handler
// runs, and until now none of them had a test. They are parsers, so their
// failure mode is quiet: silently accepting something they should reject, or
// rejecting something a client is entitled to send. Nothing here is a
// behavioural wish list — each case pins what the code does today so a
// refactor that drops one of the deliberate decisions in this file
// (DisallowUnknownFields, the 413 mapping, the dec.More() check, the cursor
// validation) fails loudly instead of shipping.

// v1CommonTestBody stands in for the real v1 input structs. A local type keeps
// these tests pinned to decodeV1 rather than to whichever fields
// v1EntryInput happens to carry.
type v1CommonTestBody struct {
	Name     string `json:"name"`
	Calories int    `json:"calories"`
}

// bodyKind selects how the request body is constructed. The three "no body"
// shapes are not interchangeable: only a literally nil r.Body takes decodeV1's
// explicit nil branch.
type bodyKind int

const (
	bodyString bodyKind = iota // a real body with the given bytes
	bodyNoBody                 // http.NoBody — what httptest.NewRequest(…, nil) produces
	bodyNil                    // r.Body == nil, which a net/http server never produces but a direct caller can
)

func TestDecodeV1(t *testing.T) {
	// Valid JSON, valid shape, but longer than maxV1Body once decoded.
	oversize := `{"name":"` + strings.Repeat("x", maxV1Body) + `"}`

	tests := []struct {
		name string
		kind bodyKind
		body string

		wantStatus int // 0 = decodeV1 must return nil
		wantSlug   string
		wantDetail string
		wantParams []apierr.InvalidParam
		wantDst    v1CommonTestBody
	}{
		{
			name:    "valid body decodes",
			body:    `{"name":"apple","calories":95}`,
			wantDst: v1CommonTestBody{Name: "apple", Calories: 95},
		},
		{
			name:    "absent fields keep their zero value",
			body:    `{}`,
			wantDst: v1CommonTestBody{},
		},
		{
			// The whole point of the manual strings.CutPrefix: a typo'd field
			// must come back named, not as a generic parse failure.
			name:       "unknown field is a 400 that names the field",
			body:       `{"calorie":500}`,
			wantStatus: http.StatusBadRequest,
			wantSlug:   "bad-request",
			wantDetail: `Unknown field "calorie".`,
		},
		{
			name:       "unknown field named even when other fields are valid",
			body:       `{"name":"apple","calorie":500}`,
			wantStatus: http.StatusBadRequest,
			wantSlug:   "bad-request",
			wantDetail: `Unknown field "calorie".`,
		},
		{
			name:       "wrong field type is a 422 naming the field and the expected type",
			body:       `{"calories":"lots"}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantSlug:   "validation-failed",
			wantDetail: "A field has the wrong type.",
			wantParams: []apierr.InvalidParam{{Name: "calories", Reason: "expected int"}},
		},
		{
			name:       "wrong field type reports the JSON name, not the Go name",
			body:       `{"name":5}`,
			wantStatus: http.StatusUnprocessableEntity,
			wantSlug:   "validation-failed",
			wantDetail: "A field has the wrong type.",
			wantParams: []apierr.InvalidParam{{Name: "name", Reason: "expected string"}},
		},
		{
			name:       "malformed JSON",
			body:       `{"name":`,
			wantStatus: http.StatusBadRequest,
			wantSlug:   "bad-request",
			wantDetail: "The request body is not valid JSON.",
		},
		{
			name:       "empty body",
			body:       ``,
			wantStatus: http.StatusBadRequest,
			wantSlug:   "bad-request",
			wantDetail: "The request body is not valid JSON.",
		},
		{
			name:       "whitespace-only body",
			body:       "  \n\t ",
			wantStatus: http.StatusBadRequest,
			wantSlug:   "bad-request",
			wantDetail: "The request body is not valid JSON.",
		},
		{
			// http.NoBody is an empty *reader*, not a nil body, so it reaches
			// the decoder and comes back as EOF. Pinned because it is what
			// httptest.NewRequest(…, nil) hands you and it is easy to mistake
			// for the nil branch below.
			name:       "http.NoBody is an empty body, not an absent one",
			kind:       bodyNoBody,
			wantStatus: http.StatusBadRequest,
			wantSlug:   "bad-request",
			wantDetail: "The request body is not valid JSON.",
		},
		{
			name:       "nil body",
			kind:       bodyNil,
			wantStatus: http.StatusBadRequest,
			wantSlug:   "bad-request",
			wantDetail: "A JSON request body is required.",
		},
		{
			// 413, not 400: an oversize body is a size problem the caller can
			// act on, and collapsing it into "not valid JSON" would send them
			// hunting for a syntax error that isn't there.
			name:       "body over maxV1Body is 413, not 400",
			body:       oversize,
			wantStatus: http.StatusRequestEntityTooLarge,
			wantSlug:   "body-too-large",
			wantDetail: fmt.Sprintf("The request body exceeds the %d byte limit.", maxV1Body),
		},
		{
			// The dec.More() check. Without it the second object is silently
			// dropped and the caller gets a 2xx for a request half of which
			// was ignored.
			name:       "two concatenated objects",
			body:       `{}{}`,
			wantStatus: http.StatusBadRequest,
			wantSlug:   "bad-request",
			wantDetail: "The request body must contain exactly one JSON object.",
		},
		{
			name:       "object followed by garbage",
			body:       `{"name":"apple"} nonsense`,
			wantStatus: http.StatusBadRequest,
			wantSlug:   "bad-request",
			wantDetail: "The request body must contain exactly one JSON object.",
		},
		{
			// Was a 422 carrying {"name": "", "reason": "expected
			// handler.v1CommonTestBody"} — an empty invalid_params name and an
			// internal Go type leaked to the caller. See the comment in
			// decodeV1.
			name:       "bare JSON array",
			body:       `[1,2]`,
			wantStatus: http.StatusBadRequest,
			wantSlug:   "bad-request",
			wantDetail: "The request body must be a JSON object.",
		},
		{
			name:       "bare JSON string",
			body:       `"apple"`,
			wantStatus: http.StatusBadRequest,
			wantSlug:   "bad-request",
			wantDetail: "The request body must be a JSON object.",
		},
		{
			name:       "bare JSON number",
			body:       `42`,
			wantStatus: http.StatusBadRequest,
			wantSlug:   "bad-request",
			wantDetail: "The request body must be a JSON object.",
		},
		{
			// KNOWN GAP, pinned rather than fixed here: encoding/json treats a
			// null literal as "leave the destination alone", so decodeV1
			// accepts it and the handler proceeds with a zero-valued struct —
			// indistinguishable from `{}`. On PUT /api/v1/notes/{date} that
			// means a body of `null` deletes the note. Tracked separately; if
			// this case starts failing because null is now rejected, that is
			// the fix landing and this expectation should flip.
			name:    "bare JSON null is accepted as an empty object",
			body:    `null`,
			wantDst: v1CommonTestBody{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var dst v1CommonTestBody
			w := httptest.NewRecorder()
			r := newDecodeReq(tt.kind, tt.body)

			got := decodeV1(w, r, &dst)

			if tt.wantStatus == 0 {
				if got != nil {
					t.Fatalf("decodeV1 = %d %q, want success", got.Status, got.Detail)
				}
				if dst != tt.wantDst {
					t.Errorf("dst = %+v, want %+v", dst, tt.wantDst)
				}
				return
			}

			if got == nil {
				t.Fatalf("decodeV1 accepted %q, want %d", tt.body, tt.wantStatus)
			}
			if got.Status != tt.wantStatus {
				t.Errorf("status = %d, want %d", got.Status, tt.wantStatus)
			}
			if want := "https://schautrack.com/problems/" + tt.wantSlug; got.Type != want {
				t.Errorf("type = %q, want %q", got.Type, want)
			}
			if got.Detail != tt.wantDetail {
				t.Errorf("detail = %q, want %q", got.Detail, tt.wantDetail)
			}
			if len(got.InvalidParams) != len(tt.wantParams) {
				t.Fatalf("invalid_params = %+v, want %+v", got.InvalidParams, tt.wantParams)
			}
			for i, p := range tt.wantParams {
				if got.InvalidParams[i] != p {
					t.Errorf("invalid_params[%d] = %+v, want %+v", i, got.InvalidParams[i], p)
				}
			}
			// Invariant #3 wants problem details a client can act on. An
			// empty param name is not one, and neither is an internal Go
			// identifier — both were real output before the top-level
			// mismatch was split off from the field mismatch.
			for i, p := range got.InvalidParams {
				if p.Name == "" {
					t.Errorf("invalid_params[%d] has an empty name: %+v", i, p)
				}
			}
			for _, s := range append([]string{got.Detail}, paramReasons(got)...) {
				if strings.Contains(s, "handler.") || strings.Contains(s, "v1CommonTestBody") {
					t.Errorf("problem text leaks an internal Go type: %q", s)
				}
			}
		})
	}
}

func newDecodeReq(kind bodyKind, body string) *http.Request {
	switch kind {
	case bodyNoBody:
		return httptest.NewRequest(http.MethodPost, "/api/v1/entries", nil)
	case bodyNil:
		r := httptest.NewRequest(http.MethodPost, "/api/v1/entries", nil)
		r.Body = nil
		return r
	default:
		return httptest.NewRequest(http.MethodPost, "/api/v1/entries", strings.NewReader(body))
	}
}

func paramReasons(p *apierr.Problem) []string {
	out := make([]string, 0, len(p.InvalidParams))
	for _, ip := range p.InvalidParams {
		out = append(out, ip.Reason)
	}
	return out
}

// TestDecodeV1UnknownFieldBeatsOtherErrors pins the ordering inside decodeV1:
// the unknown-field string match runs after the typed checks, so a body that
// is both oversize and wrong-typed reports the size first. Ordering matters
// because only one problem is ever returned.
func TestDecodeV1ErrorPrecedence(t *testing.T) {
	// Oversize wins over the unknown field it also contains.
	body := `{"nope":"` + strings.Repeat("x", maxV1Body) + `"}`
	var dst v1CommonTestBody
	got := decodeV1(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &dst)
	if got == nil || got.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body with an unknown field = %v, want 413", got)
	}

	// The unknown field is reported before a later wrong-typed field, because
	// the decoder stops at the first problem it meets.
	got = decodeV1(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"nope":1,"calories":"x"}`)), &dst)
	if got == nil || got.Status != http.StatusBadRequest {
		t.Fatalf("unknown field before type error = %v, want 400", got)
	}
	if got.Detail != `Unknown field "nope".` {
		t.Errorf("detail = %q, want the unknown field named", got.Detail)
	}
}

// TestDecodeV1OptionalTypeErrorNamesTheField covers the seam between invariant
// #7 and decodeV1: Optional[T].UnmarshalJSON delegates to json.Unmarshal, and
// the error it returns must still come back with the JSON field name attached
// rather than an empty one.
func TestDecodeV1OptionalTypeErrorNamesTheField(t *testing.T) {
	var dst v1EntryPatch
	got := decodeV1(httptest.NewRecorder(),
		httptest.NewRequest(http.MethodPatch, "/", strings.NewReader(`{"protein_g":"lots"}`)), &dst)
	if got == nil {
		t.Fatal("decodeV1 accepted a string for protein_g")
	}
	if got.Status != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", got.Status)
	}
	want := apierr.InvalidParam{Name: "protein_g", Reason: "expected int"}
	if len(got.InvalidParams) != 1 || got.InvalidParams[0] != want {
		t.Errorf("invalid_params = %+v, want [%+v]", got.InvalidParams, want)
	}
}

func TestPathID(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		omit    bool // no chi route context at all
		want    int
		wantErr bool
	}{
		{name: "one", in: "1", want: 1},
		{name: "large", in: "2147483647", want: 2147483647},
		// pathID rejects <= 0, so /entries/0 and /entries/-1 are 400s rather
		// than 404s. Deliberate: no row can ever have those ids, so a lookup
		// would be a wasted query, and 400 tells the caller the id itself is
		// wrong rather than implying the row was deleted.
		{name: "zero", in: "0", wantErr: true},
		{name: "negative", in: "-1", wantErr: true},
		{name: "not a number", in: "abc", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "decimal", in: "1.0", wantErr: true},
		{name: "leading space", in: " 1", wantErr: true},
		{name: "overflows int64", in: "9999999999999999999", wantErr: true},
		{name: "missing route param", omit: true, wantErr: true},
		// strconv.Atoi is not canonical: these are aliases for 1, so
		// /entries/01 and /entries/+1 resolve to the same row as /entries/1.
		{name: "leading zero is accepted", in: "01", want: 1},
		{name: "explicit plus is accepted", in: "+1", want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/entries/x", nil)
			if !tt.omit {
				r = withChiURLParam(r, "id", tt.in)
			}

			got, prob := pathID(r)
			if tt.wantErr {
				if prob == nil {
					t.Fatalf("pathID(%q) = %d, want a problem", tt.in, got)
				}
				assertBadRequest(t, prob, "The id must be a positive integer.")
				if got != 0 {
					t.Errorf("pathID returned %d alongside a problem, want 0", got)
				}
				return
			}
			if prob != nil {
				t.Fatalf("pathID(%q) = %v, want %d", tt.in, prob, tt.want)
			}
			if got != tt.want {
				t.Errorf("pathID(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

// dateSamples is a representative slice of the isValidDate table in
// validate_test.go. The date helpers are thin wrappers, so rather than restate
// which of these are valid, the tests below assert that each helper agrees
// with isValidDate — a property that keeps holding if the calendar rules move.
var dateSamples = []string{
	"2026-07-03", "2024-02-29", "1900-01-01", "2200-12-31",
	"", "not-a-date", "2026/07/03", "2026-7-3", "20260703",
	"2026-02-31", "2023-02-29", "2026-13-01", "2026-01-32",
	"1899-12-31", "2201-01-01", "2026-07-03x", "2026-07-03T00:00:00Z",
}

func TestPathDate(t *testing.T) {
	for _, in := range dateSamples {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			r := withChiURLParam(httptest.NewRequest(http.MethodGet, "/api/v1/weight/x", nil), "date", in)

			got, prob := pathDate(r)
			if isValidDate(in) {
				if prob != nil {
					t.Fatalf("pathDate(%q) = %v, want it accepted", in, prob)
				}
				if got != in {
					t.Errorf("pathDate(%q) = %q, want it returned verbatim", in, got)
				}
				return
			}
			if prob == nil {
				t.Fatalf("pathDate(%q) = %q, want a problem", in, got)
			}
			assertBadRequest(t, prob, "The date must be in YYYY-MM-DD format.")
			if got != "" {
				t.Errorf("pathDate returned %q alongside a problem, want \"\"", got)
			}
		})
	}

	t.Run("missing route param", func(t *testing.T) {
		got, prob := pathDate(httptest.NewRequest(http.MethodGet, "/api/v1/weight/x", nil))
		if prob == nil {
			t.Fatalf("pathDate with no route param = %q, want a problem", got)
		}
		assertBadRequest(t, prob, "The date must be in YYYY-MM-DD format.")
	})
}

func TestQueryDate(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		// Absent is not an error: the parameter is optional, and "" is the
		// signal every caller checks for.
		got, prob := queryDate(httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil), "from")
		if prob != nil {
			t.Fatalf("queryDate(absent) = %v, want no problem", prob)
		}
		if got != "" {
			t.Errorf("queryDate(absent) = %q, want \"\"", got)
		}
	})

	// A present-but-empty or whitespace-only value is treated exactly like an
	// absent one — ?from= is "I did not filter", not "I filtered on garbage".
	for _, in := range []string{"", " ", "\t", "   "} {
		t.Run(fmt.Sprintf("blank %q", in), func(t *testing.T) {
			got, prob := queryDate(reqWithQuery("from", in), "from")
			if prob != nil {
				t.Fatalf("queryDate(%q) = %v, want no problem", in, prob)
			}
			if got != "" {
				t.Errorf("queryDate(%q) = %q, want \"\"", in, got)
			}
		})
	}

	for _, in := range dateSamples {
		if in == "" {
			continue // covered by the blank cases above
		}
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			got, prob := queryDate(reqWithQuery("from", in), "from")
			if isValidDate(in) {
				if prob != nil {
					t.Fatalf("queryDate(%q) = %v, want it accepted", in, prob)
				}
				if got != in {
					t.Errorf("queryDate(%q) = %q", in, got)
				}
				return
			}
			if prob == nil {
				t.Fatalf("queryDate(%q) = %q, want a problem", in, got)
			}
			assertBadRequest(t, prob, `"from" must be in YYYY-MM-DD format.`)
			if got != "" {
				t.Errorf("queryDate returned %q alongside a problem", got)
			}
		})
	}

	t.Run("problem names the parameter", func(t *testing.T) {
		// The detail quotes the caller's own parameter name, so ?to=garbage
		// does not send them looking at ?from=.
		_, prob := queryDate(reqWithQuery("to", "garbage"), "to")
		if prob == nil {
			t.Fatal("want a problem")
		}
		assertBadRequest(t, prob, `"to" must be in YYYY-MM-DD format.`)
	})
}

// TestDateHelpersDisagreeOnWhitespace pins the one behavioural difference
// between the two date helpers. queryDate trims because a query string is
// hand-assembled and a stray space is a client-side accident; pathDate does
// not, because a path segment with a space in it is a different URL and
// silently accepting it would make " 2026-07-03" and "2026-07-03" two names
// for one resource.
func TestDateHelpersDisagreeOnWhitespace(t *testing.T) {
	const padded = " 2026-07-03 "

	got, prob := queryDate(reqWithQuery("from", padded), "from")
	if prob != nil {
		t.Fatalf("queryDate(%q) = %v, want it trimmed and accepted", padded, prob)
	}
	if got != "2026-07-03" {
		t.Errorf("queryDate(%q) = %q, want %q", padded, got, "2026-07-03")
	}

	r := withChiURLParam(httptest.NewRequest(http.MethodGet, "/api/v1/weight/x", nil), "date", padded)
	got, prob = pathDate(r)
	if prob == nil {
		t.Fatalf("pathDate(%q) = %q, want it rejected", padded, got)
	}
	assertBadRequest(t, prob, "The date must be in YYYY-MM-DD format.")
}

func TestQueryLimit(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		absent  bool
		want    int
		wantErr bool
	}{
		{name: "absent", absent: true, want: defaultPageSize},
		{name: "empty", in: "", want: defaultPageSize},
		{name: "whitespace only", in: "   ", want: defaultPageSize},
		{name: "one", in: "1", want: 1},
		{name: "default", in: strconv.Itoa(defaultPageSize), want: defaultPageSize},
		{name: "exactly max", in: strconv.Itoa(maxPageSize), want: maxPageSize},
		// Asymmetry worth pinning: above the cap the value is silently clamped,
		// but at or below zero it is a 400. Clamping is safe (the caller gets
		// fewer rows than asked and the cursor tells them there are more),
		// whereas 0 or -1 has no defensible interpretation.
		{name: "over max is clamped", in: strconv.Itoa(maxPageSize + 1), want: maxPageSize},
		{name: "far over max is clamped", in: "1000000", want: maxPageSize},
		{name: "zero is rejected", in: "0", wantErr: true},
		{name: "negative is rejected", in: "-1", wantErr: true},
		{name: "not a number", in: "abc", wantErr: true},
		{name: "decimal", in: "1.5", wantErr: true},
		{name: "hex", in: "0x10", wantErr: true},
		{name: "overflows int64", in: "99999999999999999999", wantErr: true},
		// Trimmed, unlike pathID's operand.
		{name: "surrounding whitespace is trimmed", in: " 5 ", want: 5},
		{name: "explicit plus is accepted", in: "+5", want: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil)
			if !tt.absent {
				r = reqWithQuery("limit", tt.in)
			}

			got, prob := queryLimit(r)
			if tt.wantErr {
				if prob == nil {
					t.Fatalf("queryLimit(%q) = %d, want a problem", tt.in, got)
				}
				assertBadRequest(t, prob, `"limit" must be a positive integer.`)
				if got != 0 {
					t.Errorf("queryLimit returned %d alongside a problem, want 0", got)
				}
				return
			}
			if prob != nil {
				t.Fatalf("queryLimit(%q) = %v, want %d", tt.in, prob, tt.want)
			}
			if got != tt.want {
				t.Errorf("queryLimit(%q) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}

	t.Run("never exceeds maxPageSize", func(t *testing.T) {
		// The clamp is what stops a caller asking for a million rows in one
		// query; assert it as a property, not just at the boundary.
		for _, in := range []string{"201", "500", "9999", strconv.Itoa(math.MaxInt32)} {
			got, prob := queryLimit(reqWithQuery("limit", in))
			if prob != nil {
				t.Fatalf("queryLimit(%q) = %v", in, prob)
			}
			if got > maxPageSize {
				t.Errorf("queryLimit(%q) = %d, exceeds maxPageSize %d", in, got, maxPageSize)
			}
		}
	})
}

// TestCursorRoundTrip is the property the pagination contract rests on: a
// cursor handed to a client comes back as the same position. If it did not,
// page 2 would start somewhere other than where page 1 ended and rows would be
// skipped or repeated.
func TestCursorRoundTrip(t *testing.T) {
	dates := []string{
		"1900-01-01", "1999-12-31", "2000-01-01", "2024-02-29",
		"2026-01-01", "2026-07-03", "2026-12-31", "2200-12-31",
	}
	ids := []int{1, 2, 9, 42, 999, 100000, math.MaxInt32, math.MaxInt}

	for _, d := range dates {
		for _, id := range ids {
			in := cursor{Date: d, ID: id}
			enc := encodeCursor(in)

			// The cursor travels in a query string, so it must survive it
			// untouched. RawURLEncoding guarantees the base64url alphabet and
			// no '=' padding; anything else would need escaping and a client
			// echoing next_cursor verbatim would break.
			if strings.ContainsAny(enc, "+/=") {
				t.Errorf("encodeCursor(%+v) = %q, contains a character that is not URL-safe", in, enc)
			}
			if esc := url.QueryEscape(enc); esc != enc {
				t.Errorf("encodeCursor(%+v) = %q, changes to %q when query-escaped", in, enc, esc)
			}

			got, err := decodeCursor(enc)
			if err != nil {
				t.Fatalf("decodeCursor(encodeCursor(%+v)) = %v", in, err)
			}
			if got != in {
				t.Errorf("round trip of %+v gave %+v", in, got)
			}
		}
	}
}

// TestCursorRoundTripThroughRequest closes the loop the handlers actually run:
// encodeCursor's output goes out as next_cursor and comes back in ?cursor=.
func TestCursorRoundTripThroughRequest(t *testing.T) {
	in := cursor{Date: "2026-07-03", ID: 4242}
	got, prob := queryCursor(reqWithQuery("cursor", encodeCursor(in)))
	if prob != nil {
		t.Fatalf("queryCursor = %v, want the cursor back", prob)
	}
	if got == nil || *got != in {
		t.Errorf("queryCursor = %+v, want %+v", got, in)
	}
}

// TestEncodeCursorDoesNotValidate pins the asymmetry in the codec: encoding is
// unchecked and decoding is strict. It is not a bug — encodeCursor is only ever
// fed values that came out of the database — but it means the round trip is
// only a property of well-formed cursors, and a future caller that encodes
// something odd gets a token that cannot be decoded rather than a silent
// mis-seek.
func TestEncodeCursorDoesNotValidate(t *testing.T) {
	for _, c := range []cursor{
		{Date: "", ID: 1},
		{Date: "2026-01-01", ID: 0},
		{Date: "2026-01-01", ID: -5},
		{Date: "not-a-date", ID: 3},
		{Date: "2026-01-01,extra", ID: 3},
	} {
		if _, err := decodeCursor(encodeCursor(c)); err == nil {
			t.Errorf("encodeCursor(%+v) produced a token decodeCursor accepts", c)
		}
	}
}

// TestDecodeCursorRejectsTampering is the security-adjacent half. The cursor is
// user-supplied and its (date, id) go straight into the keyset predicate, so
// every payload that is not exactly one valid date and one positive integer
// must be refused. It is not an authorization boundary — the query is always
// scoped by user_id, so a forged cursor can at worst move the caller around
// their own rows — but a malformed one reaching the query is either a database
// error (a 500 for what is a client mistake) or a silently wrong page.
func TestDecodeCursorRejectsTampering(t *testing.T) {
	enc := func(payload string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(payload))
	}

	tests := []struct {
		name string
		in   string
	}{
		{"not base64 at all", "!!! not base64 !!!"},
		{"invalid base64 length", "a"},
		{"padding only", "===="},
		// The codec is RawURLEncoding, so a client that re-encodes the payload
		// with standard base64 gets rejected rather than half-decoded.
		{"standard base64 padding", base64.StdEncoding.EncodeToString([]byte("2026-01-01,15"))},
		{"base64 of garbage", enc("garbage")},
		{"empty payload", enc("")},
		{"no comma", enc("2026-01-01")},
		{"comma only", enc(",")},
		{"empty date", enc(",5")},
		{"invalid date", enc("not-a-date,5")},
		{"impossible date", enc("2026-02-31,5")},
		{"non-padded date", enc("2026-1-1,5")},
		{"date below the sane range", enc("1899-12-31,5")},
		{"date above the sane range", enc("2201-01-01,5")},
		{"date with leading space", enc(" 2026-01-01,5")},
		{"timestamp instead of date", enc("2026-01-01T00:00:00Z,5")},
		{"id zero", enc("2026-01-01,0")},
		{"negative id", enc("2026-01-01,-1")},
		{"non-numeric id", enc("2026-01-01,abc")},
		{"empty id", enc("2026-01-01,")},
		{"id with leading space", enc("2026-01-01, 5")},
		{"extra comma", enc("2026-01-01,1,2")},
		{"id overflows int64", enc("2026-01-01,9999999999999999999")},
		{"sql fragment as id", enc("2026-01-01,1 OR 1=1")},
		{"sql fragment as date", enc("2026-01-01' OR '1'='1,5")},
		{"nul byte in payload", enc("2026-01-01\x00,5")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeCursor(tt.in)
			if err == nil {
				t.Fatalf("decodeCursor(%q) = %+v, want an error", tt.in, got)
			}
			// The error message is deliberately uniform: which part of the
			// token was wrong is of no use to a legitimate caller (who copies
			// next_cursor verbatim) and of some use to anyone probing it.
			if err.Error() != "malformed cursor" {
				t.Errorf("error = %q, want %q", err.Error(), "malformed cursor")
			}
			// A caller that forgets to check err must not end up with a
			// usable position.
			if got != (cursor{}) {
				t.Errorf("decodeCursor(%q) = %+v alongside an error, want the zero cursor", tt.in, got)
			}
		})
	}
}

func TestQueryCursor(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		got, prob := queryCursor(httptest.NewRequest(http.MethodGet, "/api/v1/entries", nil))
		if prob != nil || got != nil {
			t.Fatalf("queryCursor(absent) = %+v, %v; want nil, nil", got, prob)
		}
	})

	// Present-but-blank means "first page", the same as absent. A 400 here
	// would break a client that always appends &cursor= and leaves it empty on
	// the first request.
	for _, in := range []string{"", " ", "\t "} {
		t.Run(fmt.Sprintf("blank %q", in), func(t *testing.T) {
			got, prob := queryCursor(reqWithQuery("cursor", in))
			if prob != nil || got != nil {
				t.Fatalf("queryCursor(%q) = %+v, %v; want nil, nil", in, got, prob)
			}
		})
	}

	t.Run("tampered cursor is a 400", func(t *testing.T) {
		got, prob := queryCursor(reqWithQuery("cursor", "not-a-cursor"))
		if prob == nil {
			t.Fatalf("queryCursor = %+v, want a problem", got)
		}
		assertBadRequest(t, prob,
			"The cursor is malformed. Use the next_cursor value from a previous response verbatim.")
		if got != nil {
			t.Errorf("queryCursor returned %+v alongside a problem, want nil", got)
		}
	})
}

// --- helpers --------------------------------------------------------------

func reqWithQuery(name, value string) *http.Request {
	q := url.Values{name: []string{value}}
	return httptest.NewRequest(http.MethodGet, "/api/v1/entries?"+q.Encode(), nil)
}

func assertBadRequest(t *testing.T, p *apierr.Problem, wantDetail string) {
	t.Helper()
	if p.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", p.Status)
	}
	if p.Type != "https://schautrack.com/problems/bad-request" {
		t.Errorf("type = %q, want the bad-request type", p.Type)
	}
	if p.Detail != wantDetail {
		t.Errorf("detail = %q, want %q", p.Detail, wantDetail)
	}
}
