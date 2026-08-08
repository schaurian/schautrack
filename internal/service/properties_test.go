package service

import (
	"math"
	"testing"

	"pgregory.net/rapid"
)

// Property-based tests for the numeric/domain helpers.
//
// These complement the fuzz targets rather than duplicating them. The existing
// FuzzXxx functions take []byte or string and ask "does this crash or reject
// cleanly?" — the right question for a parser fed hostile input. The functions
// here take floats and ints that are already valid, and the interesting
// question is not whether they crash but whether the numbers they produce
// still relate to each other correctly. That is a property, and a
// table-driven test can only assert it at the handful of points somebody
// thought to write down.
//
// Each property below is paired with the user-visible consequence of it being
// false, because a property nobody can explain the failure of is a property
// that gets deleted the first time it goes red.

// weightKg generates plausible body weights. Bounded rather than unbounded
// because the guards in these functions are the subject of separate
// assertions; here the point is the arithmetic on values that pass them.
func weightKg(t *rapid.T) float64 {
	return rapid.Float64Range(1, 500).Draw(t, "weightKg")
}

// bodyFatPct generates percentages strictly inside the range the guards
// accept — (0, 100), matching ParseBodyFat.
func bodyFatPct(t *rapid.T) float64 {
	return rapid.Float64Range(0.01, 99.99).Draw(t, "bodyFatPct")
}

// TestLeanPlusFatIsTheWholeWeight is the property the planner's body
// composition card depends on. Lean mass and fat mass are computed
// independently from the same two numbers and displayed side by side; if they
// stop summing to the weight, the card shows a body that weighs something
// other than what the user just logged, and the Katch-McArdle BMR built on
// lean mass is wrong by the same amount.
func TestLeanPlusFatIsTheWholeWeight(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		w := weightKg(t)
		bf := bodyFatPct(t)

		lean := LeanBodyMass(w, bf)
		fat := FatMass(w, bf)

		// Relative tolerance: the two are w*(1-p) and w*p, so the error scales
		// with w rather than being absolute.
		if diff := math.Abs((lean + fat) - w); diff > 1e-9*math.Max(1, w) {
			t.Fatalf("LeanBodyMass(%v, %v) + FatMass(%v, %v) = %v, want %v (off by %v)",
				w, bf, w, bf, lean+fat, w, diff)
		}
	})
}

// TestLeanAndFatRejectTheSameInputs pins that the two guards move together.
// They are written out separately in each function, so nothing but a test
// stops one being relaxed without the other — which would produce a body
// composition with fat mass and no lean mass (or the reverse), and a BMR of
// 0 sitting next to a plausible-looking fat figure.
//
// It asserts on the guard condition rather than on "both results are
// non-zero", which is a weaker claim than it looks. The first version of this
// test made the stronger claim and rapid immediately produced
// weight=3.45e-77, bodyFat=4.58e-246: there, w*bf/100 underflows to exactly 0
// while w*(1-bf/100) does not, so the results differ even though both guards
// accepted. That is float underflow at magnitudes no weight ever reaches, not
// a disagreement between the guards — the property was overstated, not the
// code wrong.
func TestLeanAndFatRejectTheSameInputs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Deliberately spans the guard boundaries, including negatives, zero,
		// and percentages at and beyond 0 and 100.
		w := rapid.Float64Range(-100, 600).Draw(t, "weightKg")
		bf := rapid.Float64Range(-50, 150).Draw(t, "bodyFatPct")

		accepted := w > 0 && bf > 0 && bf < 100
		lean := LeanBodyMass(w, bf)
		fat := FatMass(w, bf)

		if !accepted {
			// Rejected input: both must refuse, so a bad body-fat value can
			// never reach BMRKatchMcArdle as a plausible number.
			if lean != 0 || fat != 0 {
				t.Fatalf("weight=%v bodyFat=%v is out of range but produced LeanBodyMass=%v FatMass=%v",
					w, bf, lean, fat)
			}
			return
		}

		// Accepted input: lean mass is a real fraction of the weight. (Fat mass
		// is allowed to underflow to 0 for absurdly small inputs, per above.)
		if lean <= 0 || lean > w {
			t.Fatalf("LeanBodyMass(%v, %v) = %v, want it in (0, %v]", w, bf, lean, w)
		}
	})
}

// TestLeanAndFatAreNeverNegative guards the sign. A negative mass is not a
// number the UI has any rendering for, and it would flow straight into
// BMRKatchMcArdle.
func TestLeanAndFatAreNeverNegative(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		w := rapid.Float64Range(-100, 600).Draw(t, "weightKg")
		bf := rapid.Float64Range(-50, 150).Draw(t, "bodyFatPct")

		if lean := LeanBodyMass(w, bf); lean < 0 {
			t.Fatalf("LeanBodyMass(%v, %v) = %v, want >= 0", w, bf, lean)
		}
		if fat := FatMass(w, bf); fat < 0 {
			t.Fatalf("FatMass(%v, %v) = %v, want >= 0", w, bf, fat)
		}
	})
}

// unitString generates both the units the app supports, the "lbs" alias, and
// junk — normUnit is reached from user-controlled `weight_unit` values.
func unitString(t *rapid.T) string {
	return rapid.SampledFrom([]string{"kg", "lb", "lbs", "", "KG", "pounds", "kilograms", "x"}).
		Draw(t, "unit")
}

// TestKgRoundTripPreservesTheWeight is what stops a weight drifting each time
// it crosses the unit boundary. Weights are stored in kg and displayed in the
// user's unit, so a lb user's reading makes this trip on every read and every
// write; a conversion that is not its own inverse would move the number a
// little further each save.
func TestKgRoundTripPreservesTheWeight(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.Float64Range(0.1, 1000).Draw(t, "value")
		unit := unitString(t)

		got := FromKg(ToKg(v, unit), unit)

		if diff := math.Abs(got - v); diff > 1e-9*math.Max(1, v) {
			t.Fatalf("FromKg(ToKg(%v, %q), %q) = %v, want %v (off by %v)", v, unit, unit, got, v, diff)
		}
	})
}

// TestNormUnitIsClosedAndIdempotent pins the two properties the rest of the
// unit handling assumes: normUnit only ever emits one of the two supported
// units, and normalizing an already-normalized value changes nothing.
//
// The second matters because ConvertPlanResponseToDisplayUnit stamps r.Unit
// with normUnit(unit) and then re-derives conversions from the same raw
// string; if normalizing were not idempotent, the stamp and the conversion
// could disagree about which unit the payload is in.
func TestNormUnitIsClosedAndIdempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		unit := unitString(t)

		got := normUnit(unit)
		if got != UnitKg && got != UnitLb {
			t.Fatalf("normUnit(%q) = %q, want %q or %q", unit, got, UnitKg, UnitLb)
		}
		if again := normUnit(got); again != got {
			t.Fatalf("normUnit is not idempotent: normUnit(%q) = %q, normUnit(%q) = %q",
				unit, got, got, again)
		}
	})
}

// TestKgIsTheIdentityConversion pins the fast path. Every kg user's weight
// goes through ToKg/FromKg too, and for them the functions must not touch the
// value at all — not "within a tolerance", exactly.
func TestKgIsTheIdentityConversion(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		v := rapid.Float64Range(-1000, 1000).Draw(t, "value")
		unit := rapid.SampledFrom([]string{"kg", "", "KG", "nonsense"}).Draw(t, "kgLikeUnit")

		if got := ToKg(v, unit); got != v {
			t.Fatalf("ToKg(%v, %q) = %v, want it untouched", v, unit, got)
		}
		if got := FromKg(v, unit); got != v {
			t.Fatalf("FromKg(%v, %q) = %v, want it untouched", v, unit, got)
		}
	})
}

// dotStatus generates the status strings the macro dots use, plus an unknown
// one — WorstDotStatus indexes a map, so an unranked string reads as 0.
func dotStatus(t *rapid.T) string {
	return rapid.SampledFrom([]string{"none", "zero", "under", "over", "over_threshold", "unranked"}).
		Draw(t, "status")
}

// TestWorstDotStatusIsTheMaximumRank pins the aggregation the day dots depend
// on. Each dot summarizes several macros into one colour, and the contract is
// that the worst one wins. Order-independence is the part worth generating
// for: the statuses arrive in whatever order the macros are enumerated, and a
// comparison written the wrong way round would still pass every fixed-order
// example somebody wrote by hand.
func TestWorstDotStatusIsTheMaximumRank(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		statuses := rapid.SliceOfN(rapid.Custom(dotStatus), 0, 8).Draw(t, "statuses")

		got := WorstDotStatus(statuses)

		wantRank := DotStatusRank["none"]
		for _, s := range statuses {
			if DotStatusRank[s] > wantRank {
				wantRank = DotStatusRank[s]
			}
		}
		if DotStatusRank[got] != wantRank {
			t.Fatalf("WorstDotStatus(%v) = %q (rank %d), want rank %d",
				statuses, got, DotStatusRank[got], wantRank)
		}

		// Reversing the input must not change the answer.
		reversed := make([]string, len(statuses))
		for i, s := range statuses {
			reversed[len(statuses)-1-i] = s
		}
		if other := WorstDotStatus(reversed); DotStatusRank[other] != DotStatusRank[got] {
			t.Fatalf("WorstDotStatus depends on order: %v -> %q, reversed -> %q",
				statuses, got, other)
		}
	})
}

// TestCaloriesFromMacrosMatchAtwater pins the 4/4/9 arithmetic and, more
// usefully, the nil case. ComputeCaloriesFromMacros returning nil is what
// distinguishes "this entry has no macros, leave calories alone" from "this
// entry's macros total zero calories" — collapse the two and every macro-less
// entry silently gets its calories overwritten with 0.
func TestCaloriesFromMacrosMatchAtwater(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		protein := rapid.IntRange(0, 2000).Draw(t, "protein")
		carbs := rapid.IntRange(0, 2000).Draw(t, "carbs")
		fat := rapid.IntRange(0, 2000).Draw(t, "fat")

		got := ComputeCaloriesFromMacros(protein, carbs, fat)

		if protein == 0 && carbs == 0 && fat == 0 {
			if got != nil {
				t.Fatalf("ComputeCaloriesFromMacros(0, 0, 0) = %v, want nil so calories are left untouched", *got)
			}
			return
		}

		if got == nil {
			// The explicit return is for staticcheck, not for control flow:
			// rapid.T.Fatalf does terminate, but it is not testing.T, so the
			// analyser cannot know that and reads every deref below as a
			// possible nil dereference.
			t.Fatalf("ComputeCaloriesFromMacros(%d, %d, %d) = nil, want a value", protein, carbs, fat)
			return
		}
		if want := protein*4 + carbs*4 + fat*9; *got != want {
			t.Fatalf("ComputeCaloriesFromMacros(%d, %d, %d) = %d, want %d", protein, carbs, fat, *got, want)
		}
	})
}

// TestCaloriesFromMacrosIsMonotonic pins the direction. Adding grams of
// anything can never lower the computed calories — a sign flip on one
// coefficient would still satisfy the Atwater check above at the point where
// that macro is 0.
func TestCaloriesFromMacrosIsMonotonic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		protein := rapid.IntRange(0, 1000).Draw(t, "protein")
		carbs := rapid.IntRange(0, 1000).Draw(t, "carbs")
		fat := rapid.IntRange(1, 1000).Draw(t, "fat")
		bump := rapid.IntRange(1, 100).Draw(t, "bump")

		base := ComputeCaloriesFromMacros(protein, carbs, fat)
		if base == nil {
			// See the note in TestCaloriesFromMacrosMatchAtwater: the return is
			// there so staticcheck can see that nothing below dereferences a
			// nil pointer.
			t.Fatalf("unexpected nil for (%d, %d, %d) with fat >= 1", protein, carbs, fat)
			return
		}

		for _, c := range []struct {
			name          string
			p, cb, f, min int
		}{
			{"protein", protein + bump, carbs, fat, *base},
			{"carbs", protein, carbs + bump, fat, *base},
			{"fat", protein, carbs, fat + bump, *base},
		} {
			more := ComputeCaloriesFromMacros(c.p, c.cb, c.f)
			if more == nil || *more <= c.min {
				t.Fatalf("adding %d g of %s to (%d, %d, %d) did not increase calories: %v, base %d",
					bump, c.name, protein, carbs, fat, more, *base)
			}
		}
	})
}
