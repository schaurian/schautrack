package service

import (
	"math"
	"strconv"
	"testing"
)

// FuzzParseWeight drives the weight parser with arbitrary strings.
//
// Properties asserted:
//
//   - never panics;
//   - !Ok implies Value == 0;
//   - Ok implies Value > 0 — the contract the weight_entries_positive CHECK
//     depends on. A parse that says "fine" and hands back 0 turns a 400 into
//     a 500 from Postgres (issue #302: ParseWeight("0.004") did exactly that,
//     fixed by #317; this target is what keeps it fixed);
//   - Ok implies Value <= MaxWeight;
//   - Ok implies Value is neither NaN nor ±Inf;
//   - Ok implies the accepted value re-parses to itself, so what is stored can
//     be read back and re-submitted unchanged.
func FuzzParseWeight(f *testing.F) {
	seeds := []string{
		// Accepted rows from TestParseWeight / TestParseWeightValid.
		"80.5", "80,5", "75.5", "100", "0.1", "1", "999.99", "1500", "  42.5  ",
		"75,5", "75.555", "75.554",
		// Rejected rows.
		"", "   ", "abc", "-5", "-1", "0", "1501", "12.34.56", "NaN", "Inf",
		"1234567890123",
		// Sub-rounding positives — the issue #302 class.
		"0.004", "0.001", "0.0049", "0,004",
		// Shapes strconv.ParseFloat quietly accepts that a human would not.
		"1e3", "0x1p-2", "+5", ".5", "5.", " 5",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		got := ParseWeight(input)

		if !got.Ok {
			if got.Value != 0 {
				t.Fatalf("ParseWeight(%q) rejected but carries Value %v, want 0", input, got.Value)
			}
			return
		}
		if math.IsNaN(got.Value) || math.IsInf(got.Value, 0) {
			t.Fatalf("ParseWeight(%q) = Ok with non-finite Value %v", input, got.Value)
		}
		if got.Value <= 0 {
			t.Fatalf("ParseWeight(%q) = Ok with Value %v; Ok must imply Value > 0 "+
				"(the weight_entries_positive CHECK rejects it)", input, got.Value)
		}
		if got.Value > MaxWeight {
			t.Fatalf("ParseWeight(%q) = Ok with Value %v, exceeds MaxWeight %v",
				input, got.Value, MaxWeight)
		}

		// An accepted value must survive a round-trip through its own
		// canonical rendering: the API echoes stored weights back to clients,
		// which resubmit them verbatim on edit.
		canon := strconv.FormatFloat(got.Value, 'f', -1, 64)
		if back := ParseWeight(canon); !back.Ok || back.Value != got.Value {
			t.Fatalf("ParseWeight(%q) = %v, but re-parsing its rendering %q gives %+v",
				input, got.Value, canon, back)
		}
	})
}

// FuzzParseBodyFat drives the body-fat parser with arbitrary strings.
//
// Same shape as FuzzParseWeight, against the tighter NUMERIC(4,1) column and
// the MaxBodyFatPct ceiling:
//
//   - never panics;
//   - !ok implies the returned percentage is 0;
//   - ok implies pct > 0 (weight_entries_body_fat_range CHECK);
//   - ok implies pct <= MaxBodyFatPct;
//   - ok implies pct is finite and re-parses to itself.
func FuzzParseBodyFat(f *testing.F) {
	seeds := []string{
		// Accepted rows from TestParseBodyFat.
		"24.3", "18", "  31.5  ", "22,7", "24.36", "24.34", "75", "0.1",
		// Rejected rows.
		"", "   ", "abc", "0", "-5", "75.1", "100", "NaN", "Inf",
		"1234567890123",
		// Sub-rounding positives — the issue #302 class for one decimal.
		"0.04", "0.049", "0,04", "0.01",
		// Shapes strconv.ParseFloat quietly accepts.
		"1e1", "0x1p-2", "+5", ".5", "5.",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		pct, ok := ParseBodyFat(input)

		if !ok {
			if pct != 0 {
				t.Fatalf("ParseBodyFat(%q) rejected but returned %v, want 0", input, pct)
			}
			return
		}
		if math.IsNaN(pct) || math.IsInf(pct, 0) {
			t.Fatalf("ParseBodyFat(%q) = ok with non-finite value %v", input, pct)
		}
		if pct <= 0 {
			t.Fatalf("ParseBodyFat(%q) = ok with value %v; ok must imply pct > 0 "+
				"(the weight_entries_body_fat_range CHECK rejects it)", input, pct)
		}
		if pct > MaxBodyFatPct {
			t.Fatalf("ParseBodyFat(%q) = ok with value %v, exceeds MaxBodyFatPct %v",
				input, pct, MaxBodyFatPct)
		}

		canon := strconv.FormatFloat(pct, 'f', -1, 64)
		if back, backOk := ParseBodyFat(canon); !backOk || back != pct {
			t.Fatalf("ParseBodyFat(%q) = %v, but re-parsing its rendering %q gives (%v, %v)",
				input, pct, canon, back, backOk)
		}
	})
}
