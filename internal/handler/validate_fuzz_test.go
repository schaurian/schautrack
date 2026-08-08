package handler

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// FuzzIsValidDate drives the strict YYYY-MM-DD validator with arbitrary
// strings.
//
// isValidDate guards every date that reaches a SQL query. A shape-only regex
// accepts 2026-02-31, which Postgres then rejects with a query error — a 500
// for the caller. The property below is the guarantee that stops that:
//
//   - never panics;
//   - isValidDate(s) implies time.Parse("2006-01-02", s) succeeds AND
//     Format round-trips to s exactly (so 2026-02-31 and 2026-7-3 are out);
//   - isValidDate(s) implies the year is within the sane 1900..2200 range;
//   - deterministic.
//
// It also asserts the converse for the only class where it is unambiguous: a
// string that Parse+Format round-trips and lands in range MUST be accepted,
// so the validator cannot start rejecting real dates.
func FuzzIsValidDate(f *testing.F) {
	seeds := []string{
		// Accepted rows from TestIsValidDate.
		"2026-07-03", "2024-02-29", "1900-01-01", "2200-12-31",
		// Rejected rows.
		"", "not-a-date", "2026/07/03", "2026-7-3", "20260703",
		"2026-02-31", "2026-02-30", "2023-02-29", "2026-13-01", "2026-00-10",
		"2026-01-32", "2026-01-00", "1899-12-31", "2201-01-01",
		"2026-07-03x", "2026-07-03T00:00:00Z", " 2026-07-03 ",
		// Extra shapes worth pinning: signed and over-wide years, separators,
		// and a value time.Parse tolerates but Format does not reproduce.
		"+2026-07-03", "-2026-07-03", "02026-07-03", "2026-07-03\n",
		"0000-01-01", "9999-12-31", "2026-07-03 ", "2026-07-3",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		got := isValidDate(s)

		if again := isValidDate(s); again != got {
			t.Fatalf("isValidDate(%q) is not deterministic: %v then %v", s, got, again)
		}

		parsed, err := time.Parse("2006-01-02", s)
		roundTrips := err == nil && parsed.Format("2006-01-02") == s
		inRange := roundTrips && parsed.Year() >= minDateYear && parsed.Year() <= maxDateYear

		if got && err != nil {
			t.Fatalf("isValidDate(%q) = true but time.Parse fails: %v", s, err)
		}
		if got && !roundTrips {
			t.Fatalf("isValidDate(%q) = true but it does not round-trip: Format gives %q",
				s, parsed.Format("2006-01-02"))
		}
		if got != inRange {
			t.Fatalf("isValidDate(%q) = %v, but Parse+Format round-trip in range = %v",
				s, got, inRange)
		}
	})
}

// FuzzTruncateUTF8 drives the byte-capping helper over arbitrary strings and
// arbitrary caps.
//
// truncateUTF8 exists because byte-index slicing can cut a multi-byte rune in
// half, and Postgres rejects the result with "invalid byte sequence for
// encoding UTF8" (22021). TestTruncateUTF8 asserts three invariants per hand
// written row; those invariants are the fuzz properties, over every input
// rather than sixteen:
//
//   - never panics;
//   - the result never exceeds the cap (and is empty for a non-positive cap);
//   - the result is always a prefix of the input;
//   - a valid-UTF-8 input yields a valid-UTF-8 result;
//   - the truncation is maximal — the next rune would not have fit;
//   - a string already within the cap comes back unchanged;
//   - truncating twice at the same cap changes nothing.
func FuzzTruncateUTF8(f *testing.F) {
	seeds := []struct {
		in       string
		maxBytes int
	}{
		{"", 10}, {"hello", 10}, {"hello", 5}, {"hello world", 5},
		{"hello", 0}, {"hello", -1},
		{"🍕🍕", 8}, {"🍕🍕", 7}, {"ab🍕", 4},
		{"aé", 2}, {"€", 3}, {"€", 2},
		{"👨‍👩‍👧‍👦", 16}, {"👨‍👩‍👧‍👦", 25},
		{strings.Repeat("🍕", 5), MaxSavedFoodEmoji},
		// Real call-site caps.
		{"a name that a user typed", 120},
		// Invalid UTF-8 in, and a cap far beyond the input.
		{"\xff\xfe", 1}, {"a\xc3", 2}, {"hello", 1 << 20},
	}
	for _, s := range seeds {
		f.Add(s.in, s.maxBytes)
	}

	f.Fuzz(func(t *testing.T, in string, maxBytes int) {
		got := truncateUTF8(in, maxBytes)

		if !strings.HasPrefix(in, got) {
			t.Fatalf("truncateUTF8(%q, %d) = %q, not a prefix of the input", in, maxBytes, got)
		}
		if maxBytes <= 0 {
			if got != "" {
				t.Fatalf("truncateUTF8(%q, %d) = %q, want empty for a non-positive cap",
					in, maxBytes, got)
			}
			return
		}
		if len(got) > maxBytes {
			t.Fatalf("truncateUTF8(%q, %d) = %q, %d bytes, exceeds the cap",
				in, maxBytes, got, len(got))
		}
		if len(in) <= maxBytes && got != in {
			t.Fatalf("truncateUTF8(%q, %d) = %q, want the input unchanged", in, maxBytes, got)
		}
		if twice := truncateUTF8(got, maxBytes); twice != got {
			t.Fatalf("truncateUTF8 is not idempotent: %q -> %q -> %q", in, got, twice)
		}

		if !utf8.ValidString(in) {
			// Garbage in, garbage out is acceptable — the caller's input was
			// already unstorable. Only the prefix/cap invariants above apply.
			return
		}
		if !utf8.ValidString(got) {
			t.Fatalf("truncateUTF8(%q, %d) = %q, which is not valid UTF-8", in, maxBytes, got)
		}
		if len(got) < len(in) {
			// Maximal: one more rune would have blown the cap. Without this,
			// a helper that always returned "" would satisfy everything above.
			_, size := utf8.DecodeRuneInString(in[len(got):])
			if len(got)+size <= maxBytes {
				t.Fatalf("truncateUTF8(%q, %d) = %q but the next %d-byte rune still fits",
					in, maxBytes, got, size)
			}
		}
	})
}
