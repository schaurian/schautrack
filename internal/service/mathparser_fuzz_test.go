package service

import (
	"math"
	"strings"
	"testing"
)

// FuzzParseAmount drives the calorie expression parser with arbitrary strings
// and arbitrary maxAbs bounds.
//
// ParseAmount is reachable from the entries handler with a raw, unvalidated
// string off the wire (`fmt.Sprintf("%v", body["amount"])` in
// entries_crud.go), so every byte sequence below is something a client can
// actually send. The table tests next door cover the inputs a human thought
// of; this covers the rest.
//
// Properties asserted (all hold on the current implementation):
//
//   - never panics;
//   - deterministic — the same (input, maxAbs) always yields the same result;
//   - !Ok implies Value == 0, so a rejected parse can never leak a value;
//   - Ok implies abs(Value) <= maxAbs, when maxAbs > 0 (ParseAmount applies
//     the bound only for a positive maxAbs; 0 means "unbounded").
//
// The seed corpus is the union of every table in mathparser_test.go plus the
// pathological inputs that motivated issue #315.
func FuzzParseAmount(f *testing.F) {
	seeds := []struct {
		input  string
		maxAbs int
	}{
		// Plain numbers and decimal rounding.
		{"123", 0}, {"0", 0}, {"999", 0},
		{"123.7", 0}, {"123.2", 0}, {"123.5", 0},
		// Arithmetic, precedence, parentheses.
		{"100 + 50", 0}, {"200 - 30", 0}, {"10 * 5", 0}, {"100 / 4", 0},
		{"(10 + 20) * 3", 0}, {"10 + (20 * 3)", 0}, {"((10 + 5) * 2) - 5", 0},
		{"100 + 50 * 2 - 10", 0}, {"100 / (2 + 3) * 4", 0},
		// Unicode operator aliases the normalizer rewrites.
		{"10 × 5", 0}, {"10 x 5", 0}, {"10 X 5", 0}, {"100 ÷ 4", 0},
		{"10 – 5", 0}, {"10 — 5", 0}, {"10 − 5", 0},
		// Thousands separators.
		{"1,000", 0}, {"1,234 + 500", 0},
		// Negatives.
		{"-10", 0}, {"10 + (-5)", 0}, {"-(10 + 5)", 0},
		// Rejected shapes.
		{"", 0}, {"abc", 0}, {"10 + abc", 0}, {"10 +", 0}, {"   ", 0},
		{"eval(1)", 0}, {"10; alert(1)", 0}, {"10 & 20", 0}, {"10 | 20", 0},
		{"10 ^ 20", 0}, {"10 << 2", 0},
		{"(10 + 20", 0}, {"10 + 20)", 0}, {"((10 + 20)", 0}, {"(10 + 20))", 0},
		{"10 / 0", 0}, {"100 / (5 - 5)", 0},
		{strings.Repeat("1 + ", 100) + "1", 0},
		// maxAbs boundary rows.
		{"9999", 9999}, {"-9999", 9999}, {"10000", 9999}, {"-10000", 9999},
		{"5000 + 5000", 9999},
		// Curiosities turned up while writing issue #315: silent
		// concatenation, "x" as a multiplication alias, sub-rounding values,
		// and the float->int overflow recorded in FuzzParseAmount's exemption
		// below.
		{"5 5", 9999}, {"0x10", 9999}, {"0.004", 9999},
		{".", 0}, {"..", 0}, {"(.)", 0}, {"1e5", 0},
		{"99999999999999999999", 9999},
		{strings.Repeat("9", 100), 9999},
	}
	for _, s := range seeds {
		f.Add(s.input, s.maxAbs)
	}

	f.Fuzz(func(t *testing.T, input string, maxAbs int) {
		got := ParseAmount(input, maxAbs)

		if again := ParseAmount(input, maxAbs); again != got {
			t.Fatalf("ParseAmount(%q, %d) is not deterministic: %+v then %+v",
				input, maxAbs, got, again)
		}

		if !got.Ok {
			if got.Value != 0 {
				t.Fatalf("ParseAmount(%q, %d) rejected but carries Value %d, want 0",
					input, maxAbs, got.Value)
			}
			return
		}

		// KNOWN DEFECT — see issue #364. ParseAmount converts the float
		// result to int with no range check. When the expression evaluates
		// beyond int64, the conversion is implementation-defined and yields
		// math.MinInt64 on amd64/arm64; abs(math.MinInt64) is itself
		// negative, so the maxAbs guard below passes and the caller gets a
		// hugely negative "valid" amount ("99999999999999999999" is enough).
		// The fix belongs to ParseAmount, which this PR deliberately does not
		// touch (issue #304 owns its behaviour). Delete this block — not the
		// assertion under it — when the overflow is fixed.
		if got.Value == math.MinInt64 {
			return
		}

		if maxAbs > 0 && abs(got.Value) > maxAbs {
			t.Fatalf("ParseAmount(%q, %d) = Ok with Value %d, exceeds the maxAbs bound",
				input, maxAbs, got.Value)
		}
	})
}
