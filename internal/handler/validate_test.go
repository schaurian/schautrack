package handler

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateUTF8(t *testing.T) {
	// Byte layout reference:
	//   "🍕" is 4 bytes, "é" is 2 bytes, "€" is 3 bytes.
	//   The family ZWJ sequence "👨‍👩‍👧‍👦" is
	//   👨(4) ZWJ(3) 👩(4) ZWJ(3) 👧(4) ZWJ(3) 👦(4) = 25 bytes.
	tests := []struct {
		name     string
		in       string
		maxBytes int
		want     string
	}{
		{"empty string", "", 10, ""},
		{"ascii under cap", "hello", 10, "hello"},
		{"ascii exactly at cap", "hello", 5, "hello"},
		{"ascii over cap", "hello world", 5, "hello"},
		{"zero cap", "hello", 0, ""},
		{"negative cap", "hello", -1, ""},
		{"emoji fits exactly at cap", "🍕🍕", 8, "🍕🍕"},
		{"emoji would be split at cap", "🍕🍕", 7, "🍕"},
		{"cap lands mid-rune after ascii", "ab🍕", 4, "ab"},
		{"two-byte rune split", "aé", 2, "a"},
		{"three-byte rune kept", "€", 3, "€"},
		{"three-byte rune split", "€", 2, ""},
		{"zwj sequence cut on rune boundary", "👨‍👩‍👧‍👦", 16, "👨‍👩‍"},
		{"zwj sequence fits", "👨‍👩‍👧‍👦", 25, "👨‍👩‍👧‍👦"},
		{"sixteen byte emoji cap", strings.Repeat("🍕", 5), MaxSavedFoodEmoji, strings.Repeat("🍕", 4)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateUTF8(tt.in, tt.maxBytes)
			if got != tt.want {
				t.Errorf("truncateUTF8(%q, %d) = %q, want %q", tt.in, tt.maxBytes, got, tt.want)
			}
			// Invariants that must hold for every input: never longer than
			// the cap, always valid UTF-8 (Postgres rejects invalid byte
			// sequences), and always a prefix of the original string.
			if tt.maxBytes >= 0 && len(got) > tt.maxBytes {
				t.Errorf("result %q is %d bytes, exceeds cap %d", got, len(got), tt.maxBytes)
			}
			if !utf8.ValidString(got) {
				t.Errorf("result %q is not valid UTF-8", got)
			}
			if !strings.HasPrefix(tt.in, got) {
				t.Errorf("result %q is not a prefix of input %q", got, tt.in)
			}
		})
	}
}

func TestIsValidDate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"valid date", "2026-07-03", true},
		{"valid leap day", "2024-02-29", true},
		{"lower bound", "1900-01-01", true},
		{"upper bound", "2200-12-31", true},
		{"empty", "", false},
		{"malformed text", "not-a-date", false},
		{"slashes instead of dashes", "2026/07/03", false},
		{"non-padded month and day", "2026-7-3", false},
		{"missing dashes", "20260703", false},
		{"impossible feb 31 (passes dateRe)", "2026-02-31", false},
		{"impossible feb 30", "2026-02-30", false},
		{"feb 29 in non-leap year", "2023-02-29", false},
		{"month 13", "2026-13-01", false},
		{"month 00", "2026-00-10", false},
		{"day 32", "2026-01-32", false},
		{"day 00", "2026-01-00", false},
		{"before sane range", "1899-12-31", false},
		{"after sane range", "2201-01-01", false},
		{"trailing garbage", "2026-07-03x", false},
		{"datetime instead of date", "2026-07-03T00:00:00Z", false},
		{"surrounding whitespace", " 2026-07-03 ", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidDate(tt.in); got != tt.want {
				t.Errorf("isValidDate(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestEntryCaloriesInRange(t *testing.T) {
	tests := []struct {
		name   string
		amount int
		want   bool
	}{
		{"zero", 0, true},
		{"typical entry", 650, true},
		{"exactly max", MaxEntryCalories, true},
		{"exactly min", -MaxEntryCalories, true},
		{"just over max", MaxEntryCalories + 1, false},
		{"just under min", -MaxEntryCalories - 1, false},
		// 999g protein + 999g carbs + 999g fat = 999*4 + 999*4 + 999*9,
		// the largest value ComputeCaloriesFromMacros can produce.
		{"max computed from macros", 16983, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := entryCaloriesInRange(tt.amount); got != tt.want {
				t.Errorf("entryCaloriesInRange(%d) = %v, want %v", tt.amount, got, tt.want)
			}
		})
	}
}

func TestMultiplyMacro(t *testing.T) {
	iptr := func(v int) *int { return &v }
	tests := []struct {
		name   string
		v      *int
		qty    int
		want   *int
		wantOk bool
	}{
		{"nil macro passes through", nil, 25, nil, true},
		{"small multiply ok", iptr(40), 24, iptr(960), true},
		{"result exactly at cap", iptr(111), 9, iptr(999), true},
		{"result over cap", iptr(40), 25, nil, false},
		{"max value qty 1", iptr(MaxEntryMacro), 1, iptr(MaxEntryMacro), true},
		{"max value qty 2", iptr(MaxEntryMacro), 2, nil, false},
		{"zero times max qty", iptr(0), 99, iptr(0), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := multiplyMacro(tt.v, tt.qty)
			if ok != tt.wantOk {
				t.Fatalf("multiplyMacro ok = %v, want %v", ok, tt.wantOk)
			}
			switch {
			case got == nil && tt.want != nil:
				t.Errorf("multiplyMacro = nil, want %d", *tt.want)
			case got != nil && tt.want == nil:
				t.Errorf("multiplyMacro = %d, want nil", *got)
			case got != nil && tt.want != nil && *got != *tt.want:
				t.Errorf("multiplyMacro = %d, want %d", *got, *tt.want)
			}
		})
	}
}
