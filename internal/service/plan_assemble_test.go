package service

import (
	"testing"
	"time"

	"schautrack/internal/model"
)

func f64(v float64) *float64 { return &v }

func TestAssemblePlan(t *testing.T) {
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)

	t.Run("metrics complete plus rate goal computes full plan", func(t *testing.T) {
		// Uses the design doc's literal worked example (130kg/180cm/age40/
		// male/moderate, 0.75 kg/week) — see
		// docs/superpowers/specs/2026-07-19-weight-loss-planner-design.md —
		// so the assertions below are an INDEPENDENT numeric reference
		// (BMR=2230, TDEE≈3456.5, deficit(0.75)=825 → budget≈2631.5, BMI≈40.1)
		// rather than a call into the same BMR/TDEE/RecommendedBudget
		// functions AssemblePlan itself wires together.
		birthYear := now.Year() - 40
		sex := "male"
		activity := "moderate"
		goal := &model.WeightGoal{
			ID: 1, UserID: 1,
			StartWeight: 130, StartDate: "2026-07-01",
			TargetWeight: 80, PaceMode: "rate", RateKgPerWeek: f64(0.75),
			Status: "active",
		}
		in := PlanInputs{
			CurrentWeight: f64(130), HeightCm: f64(180), BirthYear: &birthYear,
			Sex: &sex, ActivityLevel: &activity, Goal: goal, Now: now,
		}
		out := AssemblePlan(in)

		if !out.Metrics.Complete {
			t.Fatal("expected metrics.complete = true")
		}
		if out.Computed == nil {
			t.Fatal("expected a computed plan, got nil")
		}

		if out.Computed.BudgetKcal < 2630 || out.Computed.BudgetKcal > 2633 {
			t.Errorf("budgetKcal = %d, want 2630..2633 per the design doc's worked example", out.Computed.BudgetKcal)
		}
		if out.Computed.BudgetClamped {
			t.Error("expected budget not to be clamped at this TDEE/rate")
		}
		if len(out.Computed.PlanCurve) < 2 {
			t.Errorf("expected a non-empty planCurve, got %d points", len(out.Computed.PlanCurve))
		}
		if out.Computed.ETADate == nil {
			t.Error("expected etaDate to be set for a valid loss rate")
		}
		if out.BMI == nil || out.BMICategory == nil || out.HealthyRange == nil {
			t.Fatal("expected bmi/bmiCategory/healthyRange to be set")
		}
		if !almost(*out.BMI, 40.1, 0.1) {
			t.Errorf("bmi = %v, want ~40.1 per the design doc's worked example", *out.BMI)
		}
	})

	t.Run("no logged current weight falls back to goal start weight for BMR baseline", func(t *testing.T) {
		// CurrentWeight is nil (no weight entry logged, even though metrics
		// are complete), so AssemblePlan must derive BMR/TDEE/budget from
		// goal.StartWeight — the baseWeight fallback at plan_assemble.go's
		// baseWeight logic. StartWeight (97.3) is distinct from every other
		// weight used in this file so a wiring bug (e.g. defaulting to 0, or
		// silently reusing another case's weight) would be caught.
		birthYear := now.Year() - 35
		sex := "female"
		activity := "active"
		goal := &model.WeightGoal{
			ID: 6, UserID: 1,
			StartWeight: 97.3, StartDate: "2026-07-01",
			TargetWeight: 75, PaceMode: "rate", RateKgPerWeek: f64(0.4),
			Status: "active",
		}
		in := PlanInputs{
			CurrentWeight: nil, HeightCm: f64(170), BirthYear: &birthYear,
			Sex: &sex, ActivityLevel: &activity, Goal: goal, Now: now,
		}
		out := AssemblePlan(in)

		if !out.Metrics.Complete {
			t.Fatal("expected metrics.complete = true")
		}
		if out.Computed == nil {
			t.Fatal("expected a computed plan, got nil")
		}

		wantBMR := round1(BMR(SexFemale, goal.StartWeight, 170, 35))
		if !almost(out.Computed.BMR, wantBMR, 0.01) {
			t.Errorf("bmr = %v, want %v (must derive from goal.StartWeight, not a missing CurrentWeight)", out.Computed.BMR, wantBMR)
		}
		if out.CurrentWeight != nil {
			t.Errorf("expected currentWeight to stay nil, got %v", *out.CurrentWeight)
		}
		if out.BMI != nil {
			t.Error("expected bmi to be nil without a logged current weight")
		}
	})

	t.Run("missing metrics degrades gracefully", func(t *testing.T) {
		goal := &model.WeightGoal{
			ID: 2, UserID: 1, StartWeight: 90, StartDate: "2026-06-01",
			TargetWeight: 80, PaceMode: "rate", RateKgPerWeek: f64(0.5), Status: "active",
		}
		series := []WeightPoint{
			{Date: now.AddDate(0, 0, -20), Weight: 90},
			{Date: now.AddDate(0, 0, -10), Weight: 88},
			{Date: now, Weight: 86},
		}
		in := PlanInputs{
			CurrentWeight: f64(86), Goal: goal, Series: series, Now: now,
			// HeightCm/BirthYear/Sex/ActivityLevel intentionally left nil.
		}
		out := AssemblePlan(in)

		if out.Metrics.Complete {
			t.Error("expected metrics.complete = false")
		}
		if out.Computed != nil {
			t.Errorf("expected computed = nil with incomplete metrics, got %+v", out.Computed)
		}
		if out.Trend == nil || !out.Trend.HasData {
			t.Fatalf("expected trend to still be computed from series, got %+v", out.Trend)
		}
		if len(out.Warnings) != 0 {
			t.Errorf("expected no warnings without a computed plan, got %+v", out.Warnings)
		}
	})

	t.Run("aggressive rate clamps the budget and warns", func(t *testing.T) {
		birthYear := now.Year() - 25
		sex := "female"
		activity := "sedentary"
		goal := &model.WeightGoal{
			ID: 3, UserID: 1, StartWeight: 60, StartDate: "2026-07-01",
			TargetWeight: 50, PaceMode: "rate", RateKgPerWeek: f64(2.0), Status: "active",
		}
		in := PlanInputs{
			CurrentWeight: f64(60), HeightCm: f64(160), BirthYear: &birthYear,
			Sex: &sex, ActivityLevel: &activity, Goal: goal, Now: now,
		}
		out := AssemblePlan(in)

		if out.Computed == nil {
			t.Fatal("expected a computed plan")
		}
		if !out.Computed.BudgetClamped {
			t.Error("expected budget to be clamped for a 2kg/week rate")
		}
		if !hasWarning(out.Warnings, "budget_clamped") {
			t.Errorf("expected budget_clamped warning, got %+v", out.Warnings)
		}
		if !hasWarning(out.Warnings, "aggressive_rate") {
			t.Errorf("expected aggressive_rate warning, got %+v", out.Warnings)
		}
	})

	t.Run("underweight target warns", func(t *testing.T) {
		birthYear := now.Year() - 28
		sex := "female"
		activity := "light"
		goal := &model.WeightGoal{
			ID: 4, UserID: 1, StartWeight: 70, StartDate: "2026-07-01",
			TargetWeight: 45, PaceMode: "rate", RateKgPerWeek: f64(0.3), Status: "active",
		}
		in := PlanInputs{
			CurrentWeight: f64(70), HeightCm: f64(170), BirthYear: &birthYear,
			Sex: &sex, ActivityLevel: &activity, Goal: goal, Now: now,
		}
		out := AssemblePlan(in)

		if !hasWarning(out.Warnings, "target_underweight") {
			t.Errorf("expected target_underweight warning for a target BMI < 18.5, got %+v", out.Warnings)
		}
	})

	t.Run("current weight already past target sets goalReachedNow", func(t *testing.T) {
		goal := &model.WeightGoal{
			ID: 5, UserID: 1, StartWeight: 90, StartDate: "2026-06-01",
			TargetWeight: 70, PaceMode: "rate", RateKgPerWeek: f64(0.5), Status: "active",
		}
		in := PlanInputs{CurrentWeight: f64(65), Goal: goal, Now: now}
		out := AssemblePlan(in)

		if !out.GoalReachedNow {
			t.Error("expected goalReachedNow = true once current weight has passed the loss target")
		}
	})

	t.Run("no active goal returns nil goal-derived fields", func(t *testing.T) {
		in := PlanInputs{CurrentWeight: f64(80), HeightCm: f64(175), Now: now}
		out := AssemblePlan(in)

		if out.Goal != nil || out.Computed != nil || out.Trend != nil {
			t.Errorf("expected goal/computed/trend to be nil without an active goal, got goal=%v computed=%v trend=%v", out.Goal, out.Computed, out.Trend)
		}
		if out.GoalReachedNow {
			t.Error("expected goalReachedNow = false without an active goal")
		}
	})

	t.Run("a body-fat reading yields composition and switches BMR to Katch-McArdle", func(t *testing.T) {
		// 100kg at 30% body fat -> 70kg lean -> 370 + 21.6*70 = 1882 BMR.
		// Mifflin for the same person (180cm, 40, male) is 1930, so the
		// assertion below cannot pass by accident if the formula never switched.
		birthYear := now.Year() - 40
		sex := "male"
		activity := "sedentary"
		goal := &model.WeightGoal{
			ID: 7, UserID: 1, StartWeight: 100, StartDate: "2026-07-01",
			TargetWeight: 85, PaceMode: "rate", RateKgPerWeek: f64(0.5), Status: "active",
		}
		in := PlanInputs{
			CurrentWeight:  f64(100),
			CurrentBodyFat: &BodyFatReading{Date: "2026-07-18", WeightKg: 100, Pct: 30},
			HeightCm:       f64(180), BirthYear: &birthYear, Sex: &sex, ActivityLevel: &activity,
			Goal: goal, Now: now,
		}
		out := AssemblePlan(in)

		if out.Composition == nil {
			t.Fatal("expected composition to be derived from the body-fat reading")
		}
		if out.Composition.BodyFatPct != 30 {
			t.Errorf("bodyFatPct = %v, want 30", out.Composition.BodyFatPct)
		}
		if !almost(out.Composition.LeanMass, 70, 0.05) {
			t.Errorf("leanMass = %v, want 70", out.Composition.LeanMass)
		}
		if !almost(out.Composition.FatMass, 30, 0.05) {
			t.Errorf("fatMass = %v, want 30", out.Composition.FatMass)
		}
		if out.Composition.Category == nil || *out.Composition.Category != "obese" {
			t.Errorf("category = %v, want \"obese\" (male, 30%%)", out.Composition.Category)
		}
		if out.Composition.Date != "2026-07-18" {
			t.Errorf("composition date = %q, want the reading's own date", out.Composition.Date)
		}

		if out.Computed == nil {
			t.Fatal("expected a computed plan")
		}
		if out.Computed.BMRFormula != BMRFormulaKatch {
			t.Errorf("bmrFormula = %q, want %q", out.Computed.BMRFormula, BMRFormulaKatch)
		}
		if !almost(out.Computed.BMR, 1882, 0.05) {
			t.Errorf("bmr = %v, want 1882 (Katch-McArdle on 70kg lean), not 2035 (Mifflin)", out.Computed.BMR)
		}
	})

	t.Run("without a body-fat reading BMR stays on Mifflin-St Jeor", func(t *testing.T) {
		birthYear := now.Year() - 40
		sex := "male"
		activity := "sedentary"
		goal := &model.WeightGoal{
			ID: 8, UserID: 1, StartWeight: 100, StartDate: "2026-07-01",
			TargetWeight: 85, PaceMode: "rate", RateKgPerWeek: f64(0.5), Status: "active",
		}
		in := PlanInputs{
			CurrentWeight: f64(100),
			HeightCm:      f64(180), BirthYear: &birthYear, Sex: &sex, ActivityLevel: &activity,
			Goal: goal, Now: now,
		}
		out := AssemblePlan(in)

		if out.Composition != nil {
			t.Errorf("expected no composition without a reading, got %+v", out.Composition)
		}
		if out.Computed == nil {
			t.Fatal("expected a computed plan")
		}
		if out.Computed.BMRFormula != BMRFormulaMifflin {
			t.Errorf("bmrFormula = %q, want %q", out.Computed.BMRFormula, BMRFormulaMifflin)
		}
		// 10*100 + 6.25*180 - 5*40 + 5 = 1930
		if !almost(out.Computed.BMR, 1930, 0.05) {
			t.Errorf("bmr = %v, want 1930", out.Computed.BMR)
		}
	})

	t.Run("composition without a goal or sex still resolves what it can", func(t *testing.T) {
		// No goal, no body metrics at all: composition needs only the reading,
		// so it must survive every gate that stops Computed from being built.
		in := PlanInputs{
			CurrentWeight:  f64(80),
			CurrentBodyFat: &BodyFatReading{Date: "2026-07-19", WeightKg: 80, Pct: 20},
			Now:            now,
		}
		out := AssemblePlan(in)

		if out.Composition == nil {
			t.Fatal("expected composition without a goal or body metrics")
		}
		if !almost(out.Composition.LeanMass, 64, 0.05) {
			t.Errorf("leanMass = %v, want 64", out.Composition.LeanMass)
		}
		if out.Composition.Category != nil {
			t.Errorf("category = %v, want nil when sex is unknown", *out.Composition.Category)
		}
		if out.Computed != nil {
			t.Error("expected no computed plan without a goal")
		}
	})

	t.Run("body fat rides along on the weight series", func(t *testing.T) {
		series := []WeightPoint{
			{Date: now.AddDate(0, 0, -1), Weight: 81, BodyFat: f64(25.4)},
			{Date: now, Weight: 80}, // weight-only day, e.g. a scale without composition
		}
		out := AssemblePlan(PlanInputs{Series: series, Now: now})

		if len(out.Series) != 2 {
			t.Fatalf("series length = %d, want 2", len(out.Series))
		}
		if out.Series[0].BodyFat == nil || *out.Series[0].BodyFat != 25.4 {
			t.Errorf("series[0].bodyFat = %v, want 25.4", out.Series[0].BodyFat)
		}
		if out.Series[1].BodyFat != nil {
			t.Errorf("series[1].bodyFat = %v, want nil on a weight-only day", *out.Series[1].BodyFat)
		}
	})

	t.Run("series and disclaimer are always populated", func(t *testing.T) {
		series := []WeightPoint{{Date: now, Weight: 80}}
		out := AssemblePlan(PlanInputs{Series: series, Now: now})

		if out.Disclaimer == "" {
			t.Error("expected a non-empty disclaimer")
		}
		if len(out.Series) != 1 || out.Series[0].Date != "2026-07-19" || out.Series[0].Weight != 80 {
			t.Errorf("series = %+v, want a single 2026-07-19/80 point", out.Series)
		}
		if out.Warnings == nil {
			t.Error("expected warnings to be an empty slice, not nil")
		}
	})
}

func TestBodyFatReadingAgeDays(t *testing.T) {
	now := time.Date(2026, 7, 19, 13, 45, 0, 0, time.UTC)

	tests := []struct {
		name   string
		date   string
		want   int
		wantOK bool
	}{
		{"same day is zero, not one", "2026-07-19", 0, true},
		{"yesterday", "2026-07-18", 1, true},
		{"exactly the window", "2026-04-20", BodyFatRecencyDays, true},
		{"one day past the window", "2026-04-19", BodyFatRecencyDays + 1, true},
		{"across a leap day", "2026-02-28", 141, true},
		{"future date is negative, not an error", "2026-07-21", -2, true},
		{"garbage date does not parse", "not-a-date", 0, false},
		{"empty date does not parse", "", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := BodyFatReadingAgeDays(tt.date, now)
			if ok != tt.wantOK {
				t.Fatalf("BodyFatReadingAgeDays(%q) ok = %v, want %v", tt.date, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("BodyFatReadingAgeDays(%q) = %d, want %d", tt.date, got, tt.want)
			}
		})
	}

	t.Run("the wall-clock time of day never shifts the age", func(t *testing.T) {
		// now carries 13:45; the reading is a bare date. Truncating both to a
		// calendar day is what keeps a reading from ageing by a day mid-morning.
		early := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
		late := time.Date(2026, 7, 19, 23, 59, 59, 0, time.UTC)
		a, _ := BodyFatReadingAgeDays("2026-06-01", early)
		b, _ := BodyFatReadingAgeDays("2026-06-01", late)
		if a != b {
			t.Errorf("age changed within one calendar day: %d vs %d", a, b)
		}
	})
}

// TestAssemblePlanBodyFatRecency covers the recency window that decides whether
// a body-fat reading may pick the BMR formula. The shared profile below is
// 180cm / 40 / male / sedentary at 100kg with a 30% reading, chosen because the
// two formulas are far apart there: Katch-McArdle on 70kg of lean mass gives
// 370 + 21.6*70 = 1882, Mifflin gives 10*100 + 6.25*180 - 5*40 + 5 = 1930.
// Neither number can be produced by the other formula, so every assertion below
// fails loudly if the window is not honoured.
func TestAssemblePlanBodyFatRecency(t *testing.T) {
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	const (
		katchBMR   = 1882.0
		mifflinBMR = 1930.0
	)

	// planAt builds the shared profile with a body-fat reading taken ageDays ago.
	planAt := func(ageDays int) PlanResponse {
		birthYear := now.Year() - 40
		sex := "male"
		activity := "sedentary"
		return AssemblePlan(PlanInputs{
			CurrentWeight: f64(100),
			CurrentBodyFat: &BodyFatReading{
				Date:     now.AddDate(0, 0, -ageDays).Format("2006-01-02"),
				WeightKg: 100,
				Pct:      30,
			},
			HeightCm: f64(180), BirthYear: &birthYear, Sex: &sex, ActivityLevel: &activity,
			Goal: &model.WeightGoal{
				ID: 20, UserID: 1, StartWeight: 100, StartDate: "2026-07-01",
				TargetWeight: 85, PaceMode: "rate", RateKgPerWeek: f64(0.5), Status: "active",
			},
			Now: now,
		})
	}

	t.Run("a fresh reading selects Katch-McArdle", func(t *testing.T) {
		out := planAt(30)
		if out.Computed == nil {
			t.Fatal("expected a computed plan")
		}
		if out.Computed.BMRFormula != BMRFormulaKatch {
			t.Errorf("bmrFormula = %q, want %q for a 30-day-old reading", out.Computed.BMRFormula, BMRFormulaKatch)
		}
		if !almost(out.Computed.BMR, katchBMR, 0.05) {
			t.Errorf("bmr = %v, want %v (Katch-McArdle)", out.Computed.BMR, katchBMR)
		}
		if out.Composition == nil {
			t.Fatal("expected composition")
		}
		if out.Composition.Stale {
			t.Error("expected stale = false for a 30-day-old reading")
		}
		if out.Composition.AgeDays != 30 {
			t.Errorf("ageDays = %d, want 30", out.Composition.AgeDays)
		}
	})

	t.Run("a stale reading falls back to Mifflin-St Jeor", func(t *testing.T) {
		// Two years old: the exact scenario from issue #300. Before the window
		// existed this reported katch_mcardle — i.e. announced itself as the
		// more accurate estimate — off a percentage measured two years earlier.
		out := planAt(730)
		if out.Computed == nil {
			t.Fatal("expected a computed plan")
		}
		if out.Computed.BMRFormula != BMRFormulaMifflin {
			t.Errorf("bmrFormula = %q, want %q for a two-year-old reading", out.Computed.BMRFormula, BMRFormulaMifflin)
		}
		if !almost(out.Computed.BMR, mifflinBMR, 0.05) {
			t.Errorf("bmr = %v, want %v (Mifflin-St Jeor)", out.Computed.BMR, mifflinBMR)
		}
	})

	t.Run("a stale reading is still reported, flagged, and dated", func(t *testing.T) {
		// Dropping the reading would be the easy fix and the wrong one: the user
		// would lose the composition panel and any way to see why the plan
		// changed formula.
		out := planAt(730)
		if out.Composition == nil {
			t.Fatal("expected a stale reading to still be surfaced")
		}
		if !out.Composition.Stale {
			t.Error("expected stale = true for a two-year-old reading")
		}
		if out.Composition.AgeDays != 730 {
			t.Errorf("ageDays = %d, want 730", out.Composition.AgeDays)
		}
		if out.Composition.Date != now.AddDate(0, 0, -730).Format("2006-01-02") {
			t.Errorf("composition date = %q, want the reading's own date", out.Composition.Date)
		}
		if out.Composition.BodyFatPct != 30 {
			t.Errorf("bodyFatPct = %v, want the measured 30", out.Composition.BodyFatPct)
		}
	})

	// The boundary is pinned on both sides so a future >= / > slip, or a change
	// to BodyFatRecencyDays itself, cannot pass silently.
	t.Run("the last day inside the window still selects Katch-McArdle", func(t *testing.T) {
		out := planAt(BodyFatRecencyDays)
		if out.Computed.BMRFormula != BMRFormulaKatch {
			t.Errorf("bmrFormula at exactly %d days = %q, want %q — the window is inclusive",
				BodyFatRecencyDays, out.Computed.BMRFormula, BMRFormulaKatch)
		}
		if out.Composition.Stale {
			t.Errorf("stale = true at exactly %d days, want false", BodyFatRecencyDays)
		}
	})

	t.Run("the first day outside the window falls back to Mifflin", func(t *testing.T) {
		out := planAt(BodyFatRecencyDays + 1)
		if out.Computed.BMRFormula != BMRFormulaMifflin {
			t.Errorf("bmrFormula at %d days = %q, want %q",
				BodyFatRecencyDays+1, out.Computed.BMRFormula, BMRFormulaMifflin)
		}
		if !out.Composition.Stale {
			t.Errorf("stale = false at %d days, want true", BodyFatRecencyDays+1)
		}
	})

	t.Run("the window is 90 days", func(t *testing.T) {
		// Pinned so widening the window is a deliberate edit with a visible diff,
		// not something a refactor drifts into.
		if BodyFatRecencyDays != 90 {
			t.Errorf("BodyFatRecencyDays = %d, want 90", BodyFatRecencyDays)
		}
	})

	t.Run("a reading dated in the future counts as fresh", func(t *testing.T) {
		// The reading date is the user's local date and Now is the server's, so
		// a reading can legitimately look a few hours ahead. Treating that as
		// "infinitely stale" would break the plan for anyone east of the server.
		out := planAt(-1)
		if out.Computed.BMRFormula != BMRFormulaKatch {
			t.Errorf("bmrFormula = %q, want %q for a future-dated reading", out.Computed.BMRFormula, BMRFormulaKatch)
		}
		if out.Composition.Stale {
			t.Error("expected stale = false for a future-dated reading")
		}
	})

	t.Run("an unparseable reading date is not trusted to pick the formula", func(t *testing.T) {
		birthYear := now.Year() - 40
		sex := "male"
		activity := "sedentary"
		out := AssemblePlan(PlanInputs{
			CurrentWeight:  f64(100),
			CurrentBodyFat: &BodyFatReading{Date: "whenever", WeightKg: 100, Pct: 30},
			HeightCm:       f64(180), BirthYear: &birthYear, Sex: &sex, ActivityLevel: &activity,
			Goal: &model.WeightGoal{
				ID: 21, UserID: 1, StartWeight: 100, StartDate: "2026-07-01",
				TargetWeight: 85, PaceMode: "rate", RateKgPerWeek: f64(0.5), Status: "active",
			},
			Now: now,
		})
		if out.Computed.BMRFormula != BMRFormulaMifflin {
			t.Errorf("bmrFormula = %q, want %q when the reading date cannot be parsed",
				out.Computed.BMRFormula, BMRFormulaMifflin)
		}
		if out.Composition == nil || !out.Composition.Stale {
			t.Error("expected an undateable reading to be marked stale")
		}
	})
}

// TestAssemblePlanCompositionMatchesBMRInput is the second half of issue #300:
// the lean mass shown to the user must be the lean mass the budget was computed
// from, not the lean mass at the weight the reading happened to be taken at.
func TestAssemblePlanCompositionMatchesBMRInput(t *testing.T) {
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)

	t.Run("displayed lean mass is the weight the BMR used, not the reading's own", func(t *testing.T) {
		// 30% measured at 100kg, user now at 75kg — the worked example from the
		// issue. The reading's own weight would show 70.0kg lean; the BMR is
		// computed at 75kg, i.e. 52.5kg lean. Those are the two candidate
		// answers, and only one of them matches the budget.
		birthYear := now.Year() - 40
		sex := "male"
		activity := "sedentary"
		out := AssemblePlan(PlanInputs{
			CurrentWeight: f64(75),
			CurrentBodyFat: &BodyFatReading{
				Date: now.AddDate(0, 0, -10).Format("2006-01-02"), WeightKg: 100, Pct: 30,
			},
			HeightCm: f64(180), BirthYear: &birthYear, Sex: &sex, ActivityLevel: &activity,
			Goal: &model.WeightGoal{
				ID: 22, UserID: 1, StartWeight: 100, StartDate: "2026-07-01",
				TargetWeight: 70, PaceMode: "rate", RateKgPerWeek: f64(0.5), Status: "active",
			},
			Now: now,
		})

		if out.Composition == nil || out.Computed == nil {
			t.Fatal("expected composition and a computed plan")
		}
		if out.Computed.BMRFormula != BMRFormulaKatch {
			t.Fatalf("bmrFormula = %q, want %q — the rest of this test is about the Katch path",
				out.Computed.BMRFormula, BMRFormulaKatch)
		}
		if !almost(out.Composition.LeanMass, 52.5, 0.05) {
			t.Errorf("leanMass = %v, want 52.5 (75kg at 30%%), not 70 (the reading's own 100kg)",
				out.Composition.LeanMass)
		}
		if !almost(out.Composition.FatMass, 22.5, 0.05) {
			t.Errorf("fatMass = %v, want 22.5 (75kg at 30%%)", out.Composition.FatMass)
		}
		// The invariant, stated independently of the numbers above: inverting the
		// reported BMR through Katch-McArdle must land back on the reported lean
		// mass. 370 + 21.6*52.5 = 1504.
		leanFromBMR := (out.Computed.BMR - 370) / 21.6
		if !almost(leanFromBMR, out.Composition.LeanMass, 0.05) {
			t.Errorf("BMR %v implies %v kg of lean mass but composition reports %v — "+
				"the displayed split does not match the budget it produced",
				out.Computed.BMR, leanFromBMR, out.Composition.LeanMass)
		}
		if !almost(out.Computed.BMR, 1504, 0.05) {
			t.Errorf("bmr = %v, want 1504 per the issue's worked example", out.Computed.BMR)
		}
		// Lean + fat must still reconcile to the weight they were derived from.
		if !almost(out.Composition.LeanMass+out.Composition.FatMass, 75, 0.05) {
			t.Errorf("leanMass + fatMass = %v, want the 75kg they were derived from",
				out.Composition.LeanMass+out.Composition.FatMass)
		}
	})

	t.Run("with no logged weight the goal's start weight anchors both", func(t *testing.T) {
		// baseWeight falls back to goal.StartWeight; composition must follow it
		// rather than quietly reverting to the reading's own weight.
		birthYear := now.Year() - 40
		sex := "male"
		activity := "sedentary"
		out := AssemblePlan(PlanInputs{
			CurrentWeight: nil,
			CurrentBodyFat: &BodyFatReading{
				Date: now.AddDate(0, 0, -5).Format("2006-01-02"), WeightKg: 100, Pct: 30,
			},
			HeightCm: f64(180), BirthYear: &birthYear, Sex: &sex, ActivityLevel: &activity,
			Goal: &model.WeightGoal{
				ID: 23, UserID: 1, StartWeight: 90, StartDate: "2026-07-01",
				TargetWeight: 80, PaceMode: "rate", RateKgPerWeek: f64(0.5), Status: "active",
			},
			Now: now,
		})
		if out.Composition == nil || out.Computed == nil {
			t.Fatal("expected composition and a computed plan")
		}
		if !almost(out.Composition.LeanMass, 63, 0.05) {
			t.Errorf("leanMass = %v, want 63 (90kg start weight at 30%%)", out.Composition.LeanMass)
		}
		leanFromBMR := (out.Computed.BMR - 370) / 21.6
		if !almost(leanFromBMR, out.Composition.LeanMass, 0.05) {
			t.Errorf("BMR implies %v kg lean, composition reports %v", leanFromBMR, out.Composition.LeanMass)
		}
	})

	t.Run("with neither a weight nor a goal the reading's own weight is used", func(t *testing.T) {
		// Nothing else exists to anchor on, and no BMR is computed either, so
		// there is nothing to disagree with.
		out := AssemblePlan(PlanInputs{
			CurrentBodyFat: &BodyFatReading{Date: "2026-07-15", WeightKg: 80, Pct: 20},
			Now:            now,
		})
		if out.Composition == nil {
			t.Fatal("expected composition from the reading alone")
		}
		if !almost(out.Composition.LeanMass, 64, 0.05) {
			t.Errorf("leanMass = %v, want 64 (the reading's own 80kg at 20%%)", out.Composition.LeanMass)
		}
		if out.Computed != nil {
			t.Error("expected no computed plan without a goal")
		}
	})
}

func hasWarning(warnings []PlanWarning, code string) bool {
	for _, w := range warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}
