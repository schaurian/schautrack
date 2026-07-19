package service

// KgPerLb is the exact avoirdupois pound-to-kilogram conversion factor.
const KgPerLb = 0.45359237

// normUnit normalizes a user-supplied weight unit string. Unknown or empty
// values fall back to "kg" (schautrack's historical default), matching how
// the rest of the app treats an unset weight_unit.
func normUnit(unit string) string {
	if unit == "lb" || unit == "lbs" {
		return "lb"
	}
	return "kg"
}

// ToKg converts a weight (or weight/week rate) from the display unit to kg.
func ToKg(v float64, unit string) float64 {
	if normUnit(unit) == "lb" {
		return v * KgPerLb
	}
	return v
}

// FromKg converts a kg weight (or kg/week rate) to the display unit.
func FromKg(v float64, unit string) float64 {
	if normUnit(unit) == "lb" {
		return v / KgPerLb
	}
	return v
}

// ConvertPlanResponseToDisplayUnit converts the weight-VALUED fields of a
// kg-computed PlanResponse into the user's display unit, in place. Leaves
// unit-independent fields untouched: BMI, BMICategory, BudgetKcal, ETAWeeks,
// ProjectedWeeks, Status strings, and Metrics.HeightCm (cm, not a weight).
// Rounds to 1 decimal to match the app's weight display.
func ConvertPlanResponseToDisplayUnit(r *PlanResponse, unit string) {
	if normUnit(unit) == "kg" {
		return // identity fast-path
	}
	conv := func(p *float64) {
		if p != nil {
			*p = round1(FromKg(*p, unit))
		}
	}
	conv(r.CurrentWeight)
	for i := range r.Series {
		r.Series[i].Weight = round1(FromKg(r.Series[i].Weight, unit))
	}
	if r.HealthyRange != nil {
		r.HealthyRange.MinKg = round1(FromKg(r.HealthyRange.MinKg, unit))
		r.HealthyRange.MaxKg = round1(FromKg(r.HealthyRange.MaxKg, unit))
	}
	if r.Computed != nil {
		r.Computed.RateKgPerWeek = round1(FromKg(r.Computed.RateKgPerWeek, unit))
		for i := range r.Computed.PlanCurve {
			r.Computed.PlanCurve[i].Weight = round1(FromKg(r.Computed.PlanCurve[i].Weight, unit))
		}
	}
	if r.Trend != nil {
		r.Trend.SlopeKgPerWeek = round1(FromKg(r.Trend.SlopeKgPerWeek, unit))
	}
}
