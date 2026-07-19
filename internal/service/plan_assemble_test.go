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
		birthYear := now.Year() - 30
		sex := "male"
		activity := "moderate"
		goal := &model.WeightGoal{
			ID: 1, UserID: 1,
			StartWeight: 105, StartDate: "2026-07-01",
			TargetWeight: 90, PaceMode: "rate", RateKgPerWeek: f64(0.5),
			Status: "active",
		}
		in := PlanInputs{
			CurrentWeight: f64(105), HeightCm: f64(185), BirthYear: &birthYear,
			Sex: &sex, ActivityLevel: &activity, Goal: goal, Now: now,
		}
		out := AssemblePlan(in)

		if !out.Metrics.Complete {
			t.Fatal("expected metrics.complete = true")
		}
		if out.Computed == nil {
			t.Fatal("expected a computed plan, got nil")
		}

		// Cross-check against the same Task-2 pure functions AssemblePlan is
		// supposed to wire together, rather than hardcoding a magic constant.
		wantBMR := BMR(SexMale, 105, 185, 30)
		wantTDEE := TDEE(wantBMR, ActivityModerate)
		wantBudget, wantClamped := RecommendedBudget(wantTDEE, 0.5, DirLoss, CalorieFloor(SexMale))
		if out.Computed.BudgetKcal != wantBudget {
			t.Errorf("budgetKcal = %d, want %d (~2631 per the illustrative example)", out.Computed.BudgetKcal, wantBudget)
		}
		if out.Computed.BudgetClamped != wantClamped {
			t.Errorf("budgetClamped = %v, want %v", out.Computed.BudgetClamped, wantClamped)
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
		wantBMI := round1(BMI(105, 185))
		if !almost(*out.BMI, wantBMI, 0.01) {
			t.Errorf("bmi = %v, want %v", *out.BMI, wantBMI)
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

func hasWarning(warnings []PlanWarning, code string) bool {
	for _, w := range warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}
