package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"schautrack/internal/apierr"
	"schautrack/internal/model"
)

// FuzzDecodeCursor drives the keyset pagination cursor through both
// directions.
//
// The cursor arrives as a user-supplied query parameter, is base64-decoded,
// and its two halves are spliced into a keyset WHERE clause. A cursor that
// decodes to a bogus date or a non-positive id is a malformed query at best.
//
// Properties asserted:
//
//   - decodeCursor never panics on arbitrary input;
//   - a failed decode returns the zero cursor, never a half-filled one;
//   - success implies isValidDate(c.Date) && c.ID > 0;
//   - success is stable: re-encoding a decoded cursor decodes back to it;
//   - decodeCursor(encodeCursor(c)) == c for every cursor the encoder can
//     legitimately be handed (valid date, positive id).
func FuzzDecodeCursor(f *testing.F) {
	seeds := []struct {
		raw  string
		date string
		id   int
	}{
		{encodeCursor(cursor{Date: "2026-07-03", ID: 42}), "2026-07-03", 42},
		{encodeCursor(cursor{Date: "1900-01-01", ID: 1}), "1900-01-01", 1},
		{encodeCursor(cursor{Date: "2200-12-31", ID: 1 << 31}), "2200-12-31", 1 << 31},
		// Malformed cursors: not base64, base64 of nonsense, missing comma,
		// bad date, non-positive / non-numeric id, padded base64.
		{"", "", 0},
		{"!!!not base64!!!", "2026-02-31", 0},
		{"MjAyNi0wNy0wMw", "2026-07-03", -1},
		{"MjAyNi0wMi0zMSw0Mg", "2026-7-3", 1},
		{"MjAyNi0wNy0wMyww", "2026-07-03", 0},
		{"MjAyNi0wNy0wMyxhYmM", "not-a-date", 5},
		{"MjAyNi0wNy0wMyw0Mg==", "2026-07-03", 1<<62 + 1},
		{",,,", "2026,07,03", 7},
		{strings.Repeat("A", 400), "2026-07-03", 9223372036854775807},
	}
	for _, s := range seeds {
		f.Add(s.raw, s.date, s.id)
	}

	f.Fuzz(func(t *testing.T, raw, date string, id int) {
		// Direction 1: arbitrary bytes off the wire.
		got, err := decodeCursor(raw)
		if err != nil {
			if got != (cursor{}) {
				t.Fatalf("decodeCursor(%q) failed but returned %+v, want the zero cursor", raw, got)
			}
		} else {
			if !isValidDate(got.Date) {
				t.Fatalf("decodeCursor(%q) = %+v, but %q is not a valid date", raw, got, got.Date)
			}
			if got.ID <= 0 {
				t.Fatalf("decodeCursor(%q) = %+v, but the id must be positive", raw, got)
			}
			// A cursor we handed out must survive being handed back.
			again, err := decodeCursor(encodeCursor(got))
			if err != nil || again != got {
				t.Fatalf("re-encoding %+v does not round-trip: got %+v, err %v", got, again, err)
			}
		}

		// Direction 2: cursors the encoder can legitimately be given. Only
		// these are round-trippable — encodeCursor has no validation of its
		// own, and a caller that fabricates an invalid one is out of contract.
		c := cursor{Date: date, ID: id}
		// model.MaxID bounds the round-trippable domain for the same reason
		// c.ID <= 0 does: a cursor id names a row, every id column is int4, so
		// an id beyond that names nothing the encoder could have produced. It
		// is now rejected at decode rather than reaching pgx, which used to
		// turn a fabricated cursor into a 500.
		if !isValidDate(c.Date) || c.ID <= 0 || c.ID > model.MaxID {
			return
		}
		back, err := decodeCursor(encodeCursor(c))
		if err != nil {
			t.Fatalf("decodeCursor(encodeCursor(%+v)) failed: %v", c, err)
		}
		if back != c {
			t.Fatalf("decodeCursor(encodeCursor(%+v)) = %+v, want the original", c, back)
		}
	})
}

// FuzzDecodeV1 drives the /api/v1 body decoder with arbitrary bytes.
//
// decodeV1 is the first thing every v1 write endpoint runs against a caller's
// body, and its whole job is to turn malformed input into a precise 4xx. A
// 5xx from here would be the API blaming itself for the client's typo, and an
// unhandled panic would take the process down.
//
// Properties asserted:
//
//   - never panics on any byte sequence, against several real request shapes
//     (plain pointers, Optional[T] fields, and a bare map);
//   - the outcome is either a successful decode or a *apierr.Problem;
//   - a returned Problem always carries a 4xx status — never 5xx, never 0,
//     never a success code;
//   - a returned Problem is well-formed: non-empty type and title;
//   - deterministic for the same bytes.
func FuzzDecodeV1(f *testing.F) {
	seeds := []struct {
		body  string
		shape uint8
	}{
		{`{"calories":500}`, 0},
		{`{"date":"2026-07-03","calories":500,"name":"pizza"}`, 0},
		{`{"name":null,"protein_g":12}`, 1},
		{`{"anything":1}`, 2},
		// Malformed / hostile bodies.
		{``, 0},
		{`   `, 0},
		{`null`, 0},
		{`{`, 0},
		{`{}{}`, 0},
		{`{} garbage`, 0},
		{`[1,2,3]`, 0},
		{`{"calories":"five hundred"}`, 0},   // UnmarshalTypeError -> 422
		{`{"caloriez":500}`, 0},              // unknown field -> 400
		{`{"calories":1e309}`, 0},            // number out of float range
		{`{"name":"\ud800"}`, 0},             // lone surrogate
		{`{"name":"` + "\xff\xfe" + `"}`, 0}, // invalid UTF-8 in a string
		{strings.Repeat(`{"a":`, 200) + `1` + strings.Repeat(`}`, 200), 2},
		{`{"protein_g":{"nested":true}}`, 1},
	}
	for _, s := range seeds {
		f.Add([]byte(s.body), s.shape)
	}

	f.Fuzz(func(t *testing.T, body []byte, shape uint8) {
		first := runDecodeV1(t, body, shape)
		if second := runDecodeV1(t, body, shape); (first == nil) != (second == nil) {
			t.Fatalf("decodeV1 is not deterministic for %q", body)
		}
		if first == nil {
			return
		}
		if first.Status < 400 || first.Status > 499 {
			t.Fatalf("decodeV1(%q) returned status %d; a malformed body must always be 4xx",
				body, first.Status)
		}
		if first.Type == "" || first.Title == "" {
			t.Fatalf("decodeV1(%q) returned a malformed problem %+v", body, first)
		}
	})
}

// runDecodeV1 pushes body through decodeV1 against one of the real v1 request
// shapes. shape selects between plain-pointer fields, Optional[T] fields
// (whose custom UnmarshalJSON is its own error path), and a bare map.
func runDecodeV1(t *testing.T, body []byte, shape uint8) *apierr.Problem {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/entries", bytes.NewReader(body))
	w := httptest.NewRecorder()

	switch shape % 3 {
	case 0:
		var dst v1EntryInput
		return decodeV1(w, r, &dst)
	case 1:
		var dst v1EntryPatch
		return decodeV1(w, r, &dst)
	default:
		var dst map[string]any
		return decodeV1(w, r, &dst)
	}
}
