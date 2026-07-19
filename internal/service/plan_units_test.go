package service

import "testing"

func TestToKgFromKg(t *testing.T) {
	t.Run("kg is identity", func(t *testing.T) {
		if got := ToKg(70, "kg"); got != 70 {
			t.Errorf("ToKg(70, kg) = %v, want 70", got)
		}
		if got := FromKg(70, "kg"); got != 70 {
			t.Errorf("FromKg(70, kg) = %v, want 70", got)
		}
	})

	t.Run("empty and unknown unit fall back to kg identity", func(t *testing.T) {
		for _, unit := range []string{"", "stone", "grams"} {
			if got := ToKg(70, unit); got != 70 {
				t.Errorf("ToKg(70, %q) = %v, want 70", unit, got)
			}
			if got := FromKg(70, unit); got != 70 {
				t.Errorf("FromKg(70, %q) = %v, want 70", unit, got)
			}
		}
	})

	t.Run("lb and lbs convert to kg", func(t *testing.T) {
		for _, unit := range []string{"lb", "lbs"} {
			got := ToKg(100, unit)
			if !almost(got, 45.359237, 1e-6) {
				t.Errorf("ToKg(100, %q) = %v, want ≈45.359237", unit, got)
			}
		}
	})

	t.Run("round-trip through lb is stable", func(t *testing.T) {
		x := 83.4
		got := FromKg(ToKg(x, "lb"), "lb")
		if !almost(got, x, 1e-9) {
			t.Errorf("FromKg(ToKg(%v)) = %v, want ≈%v", x, got, x)
		}
	})
}

func TestConvertPlanResponseToDisplayUnit(t *testing.T) {
	newResp := func() *PlanResponse {
		bmi := 29.4
		return &PlanResponse{
			CurrentWeight: f64(90),
			BMI:           &bmi,
			Series:        []SeriesPoint{{Date: "2026-07-01", Weight: 91}},
			HealthyRange:  &HealthyRange{MinKg: 59.9, MaxKg: 80.7},
			Computed: &PlanComputed{
				BudgetKcal:    2000,
				RateKgPerWeek: 0.34,
				PlanCurve:     []CurvePoint{{Week: 0, Weight: 90}},
			},
			Trend: &PlanTrend{SlopeKgPerWeek: -0.3, Status: "on_track"},
		}
	}

	t.Run("kg unit is a no-op", func(t *testing.T) {
		r := newResp()
		before := *r
		ConvertPlanResponseToDisplayUnit(r, "kg")
		if *r.CurrentWeight != *before.CurrentWeight {
			t.Errorf("kg conversion should be identity, currentWeight changed to %v", *r.CurrentWeight)
		}
		if r.Series[0].Weight != 91 {
			t.Errorf("kg conversion should be identity, series weight changed to %v", r.Series[0].Weight)
		}
		if r.Computed.BudgetKcal != 2000 {
			t.Errorf("budgetKcal must never change, got %d", r.Computed.BudgetKcal)
		}
	})

	t.Run("lb unit converts weight-valued fields only", func(t *testing.T) {
		r := newResp()
		ConvertPlanResponseToDisplayUnit(r, "lb")

		if !almost(*r.CurrentWeight, 198.4, 0.1) {
			t.Errorf("CurrentWeight = %v, want ≈198.4", *r.CurrentWeight)
		}
		if !almost(r.Series[0].Weight, 200.6, 0.1) {
			t.Errorf("Series[0].Weight = %v, want ≈200.6", r.Series[0].Weight)
		}
		if !almost(r.HealthyRange.MinKg, 132.1, 0.1) {
			t.Errorf("HealthyRange.MinKg = %v, want ≈132.1", r.HealthyRange.MinKg)
		}
		if !almost(r.HealthyRange.MaxKg, 177.9, 0.1) {
			t.Errorf("HealthyRange.MaxKg = %v, want ≈177.9", r.HealthyRange.MaxKg)
		}
		if !almost(r.Computed.RateKgPerWeek, 0.7, 0.1) {
			t.Errorf("Computed.RateKgPerWeek = %v, want ≈0.7", r.Computed.RateKgPerWeek)
		}
		if !almost(r.Computed.PlanCurve[0].Weight, 198.4, 0.1) {
			t.Errorf("PlanCurve[0].Weight = %v, want ≈198.4", r.Computed.PlanCurve[0].Weight)
		}
		if !almost(r.Trend.SlopeKgPerWeek, -0.7, 0.1) {
			t.Errorf("Trend.SlopeKgPerWeek = %v, want ≈-0.7", r.Trend.SlopeKgPerWeek)
		}

		// Unit-independent fields must be untouched.
		if r.Computed.BudgetKcal != 2000 {
			t.Errorf("BudgetKcal must not be converted, got %d", r.Computed.BudgetKcal)
		}
		if *r.BMI != 29.4 {
			t.Errorf("BMI must not be converted, got %v", *r.BMI)
		}
	})

	t.Run("nil sub-structs are handled without panicking", func(t *testing.T) {
		r := &PlanResponse{CurrentWeight: f64(90)}
		ConvertPlanResponseToDisplayUnit(r, "lb")
		if !almost(*r.CurrentWeight, 198.4, 0.1) {
			t.Errorf("CurrentWeight = %v, want ≈198.4", *r.CurrentWeight)
		}
	})
}
