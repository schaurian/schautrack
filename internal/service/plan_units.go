package service

// KgPerLb is the exact avoirdupois pound-to-kilogram conversion factor.
const KgPerLb = 0.45359237

// The two weight units the app supports. These are the only values that ever
// appear in PlanResponse.Unit, and they match the `weight_unit` enum on the
// user record and the `unit` field on a v1 weight reading.
const (
	UnitKg = "kg"
	UnitLb = "lb"
)

// normUnit normalizes a user-supplied weight unit string. Unknown or empty
// values fall back to "kg" (schautrack's historical default), matching how
// the rest of the app treats an unset weight_unit.
func normUnit(unit string) string {
	if unit == UnitLb || unit == "lbs" {
		return UnitLb
	}
	return UnitKg
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
// kg-computed PlanResponse into the user's display unit, in place, and stamps
// r.Unit with the unit it left them in. Leaves unit-independent fields
// untouched: BMI, BMICategory, BudgetKcal, ETAWeeks, ProjectedWeeks, Status
// strings, Composition.BodyFatPct (a percentage), and Metrics.HeightCm (cm,
// not a weight).
// Rounds to 1 decimal to match the app's weight display.
//
// The Unit stamp happens before the kg fast-path returns, so the payload is
// labelled whether or not anything was converted. Without it the response
// would carry a pile of unit-bearing numbers and no statement of which unit
// they are in, and a client would have to fetch the account elsewhere to find
// out — the failure mode behind schaurian/schautrack#361.
func ConvertPlanResponseToDisplayUnit(r *PlanResponse, unit string) {
	r.Unit = normUnit(unit)
	if r.Unit == UnitKg {
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
	if r.Composition != nil {
		r.Composition.LeanMass = round1(FromKg(r.Composition.LeanMass, unit))
		r.Composition.FatMass = round1(FromKg(r.Composition.FatMass, unit))
	}
	if r.HealthyRange != nil {
		r.HealthyRange.Min = round1(FromKg(r.HealthyRange.Min, unit))
		r.HealthyRange.Max = round1(FromKg(r.HealthyRange.Max, unit))
	}
	if r.Computed != nil {
		r.Computed.RatePerWeek = round1(FromKg(r.Computed.RatePerWeek, unit))
		for i := range r.Computed.PlanCurve {
			r.Computed.PlanCurve[i].Weight = round1(FromKg(r.Computed.PlanCurve[i].Weight, unit))
		}
	}
	if r.Trend != nil {
		r.Trend.SlopePerWeek = round1(FromKg(r.Trend.SlopePerWeek, unit))
	}
}
