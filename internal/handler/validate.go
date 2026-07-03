package handler

import (
	"time"
	"unicode/utf8"
)

// Sane calendar-year bounds for user-supplied dates. Anything outside is a
// typo or garbage input, not a plausible entry date.
const (
	minDateYear = 1900
	maxDateYear = 2200
)

// truncateUTF8 caps s at maxBytes bytes without splitting a multi-byte UTF-8
// rune. Byte-index slicing (s[:n]) can cut an emoji or other multi-byte rune
// in half, producing invalid UTF-8 that Postgres rejects with
// "invalid byte sequence for encoding UTF8" (error 22021). If the cap lands
// mid-rune, the cut point walks back to the previous rune boundary, so the
// result is always valid UTF-8 and a prefix of s.
func truncateUTF8(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// isValidDate reports whether s is a real calendar date in strict
// YYYY-MM-DD form within a sane year range. Unlike dateRe (a shape-only
// regex), the time.Parse round-trip rejects impossible dates such as
// 2026-02-31, which Postgres would reject with a query error (a 500 for the
// caller). The Format round-trip additionally rejects non-padded forms like
// 2026-7-3 that time.Parse tolerates.
func isValidDate(s string) bool {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return false
	}
	if t.Format("2006-01-02") != s {
		return false
	}
	y := t.Year()
	return y >= minDateYear && y <= maxDateYear
}

// entryCaloriesInRange reports whether amount satisfies the calorie_entries
// amount CHECK constraint (-MaxEntryCalories..MaxEntryCalories). Used to
// validate auto-computed calories, which can reach 16983 (999g protein +
// 999g carbs + 999g fat) — far beyond what the column accepts.
func entryCaloriesInRange(amount int) bool {
	return amount >= -MaxEntryCalories && amount <= MaxEntryCalories
}

// multiplyMacro multiplies an optional macro gram value by qty. ok is false
// when the result would violate the macro column CHECK constraint
// (0..MaxEntryMacro); a nil input passes through unchanged.
func multiplyMacro(v *int, qty int) (*int, bool) {
	if v == nil {
		return nil, true
	}
	m := *v * qty
	if m < 0 || m > MaxEntryMacro {
		return nil, false
	}
	return &m, true
}
