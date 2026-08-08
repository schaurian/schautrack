package service

import (
	"math"
	"time"

	"schautrack/internal/model"
)

// PlanDisclaimer is surfaced verbatim to the client alongside every plan payload.
const PlanDisclaimer = "This plan is an estimate based on standard formulas (Mifflin-St Jeor, or Katch-McArdle when a body-fat reading is available) and general activity guidelines. " +
	"It is not medical advice — consult a healthcare professional before starting any weight-loss or weight-gain program, " +
	"especially if you have underlying health conditions."

// PlanInputs is everything AssemblePlan needs, gathered by the handler from the
// DB. AssemblePlan itself performs no I/O and does not read the wall clock.
type PlanInputs struct {
	CurrentWeight *float64 // nil if no weight logged
	// CurrentBodyFat is the most recent body-fat reading and the weight it was
	// taken with — both, because lean mass is only meaningful against the
	// weight measured at the same time, which may predate CurrentWeight.
	CurrentBodyFat *BodyFatReading
	HeightCm       *float64
	BirthYear      *int
	Sex            *string
	ActivityLevel  *string
	Goal           *model.WeightGoal // nil if none active
	Series         []WeightPoint
	CurrentCalGoal *int
	Now            time.Time
}

// BodyFatReading is one measured body-fat percentage with the weight and date
// it was recorded against.
type BodyFatReading struct {
	Date     string
	WeightKg float64
	Pct      float64
}

type PlanMetrics struct {
	HeightCm      *float64 `json:"heightCm"`
	BirthYear     *int     `json:"birthYear"`
	Sex           *string  `json:"sex"`
	ActivityLevel *string  `json:"activityLevel"`
	Complete      bool     `json:"complete"`
}

// HealthyRange is the weight band for a BMI of 18.5–24.9 at the account's
// height. Min/Max are weights, so they are in PlanResponse.Unit — which is why
// they are not called MinKg/MaxKg: for a pound account they are pounds.
type HealthyRange struct {
	Min float64 `json:"min"`
	Max float64 `json:"max"`
}

type PlanComputed struct {
	BMR           float64 `json:"bmr"`
	TDEE          float64 `json:"tdee"`
	BudgetKcal    int     `json:"budgetKcal"`
	BudgetClamped bool    `json:"budgetClamped"`
	// RatePerWeek is a weight per week and therefore in PlanResponse.Unit.
	RatePerWeek float64      `json:"ratePerWeek"`
	ETAWeeks    float64      `json:"etaWeeks"`
	ETADate     *string      `json:"etaDate"`
	PlanCurve   []CurvePoint `json:"planCurve"`
	// BMRFormula names the estimator behind BMR: "katch_mcardle" when a
	// body-fat reading was available, "mifflin_st_jeor" otherwise. Surfaced so
	// the UI can say which one produced the budget instead of the accuracy
	// upgrade being invisible.
	BMRFormula string `json:"bmrFormula"`
}

// BodyComposition is the derived view of one body-fat reading. LeanMass and
// FatMass are weights and therefore converted to the user's display unit
// alongside every other weight in the payload; BodyFatPct is a percentage and
// is never converted.
//
// LeanMass/FatMass are the percentage carried onto the weight the plan works
// from — the same weight the BMR is computed at, never the weight the reading
// happened to be taken at. Splitting those two produced a displayed lean mass
// that disagreed with the lean mass the budget came from.
type BodyComposition struct {
	Date       string  `json:"date"`
	BodyFatPct float64 `json:"bodyFatPct"`
	LeanMass   float64 `json:"leanMass"`
	FatMass    float64 `json:"fatMass"`
	Category   *string `json:"category"` // nil when sex is unknown
	// AgeDays is how many whole days before today the reading was taken, and
	// Stale reports whether that puts it outside BodyFatRecencyDays. A stale
	// reading is still returned — it is the user's most recent measurement and
	// worth showing — but it does not drive BMR. Both fields exist so the UI can
	// say how old the number is instead of presenting a two-year-old percentage
	// as current.
	AgeDays int  `json:"ageDays"`
	Stale   bool `json:"stale"`
}

// BodyFatRecencyDays bounds how old a body-fat reading may be and still choose
// the BMR formula. Body composition drifts; a percentage measured long ago and
// carried onto today's weight can move the daily budget by well over 100 kcal
// while reporting itself as the *more* accurate Katch-McArdle estimate. 90 days
// is about as long as a reading stays credible for someone who actually owns a
// composition scale, and it mirrors the recency bound the plan already applies
// to the weight series. Outside the window the plan falls back to
// Mifflin-St Jeor, which needs no composition input at all.
const BodyFatRecencyDays = 90

// BodyFatReadingAgeDays returns how many whole days old a YYYY-MM-DD reading is
// relative to now's calendar date, plus whether the date parsed at all. A
// reading dated ahead of now yields a negative age (the reading date is the
// user's local date while now is the server's, so a few hours of skew is
// normal); callers treat that as fresh rather than as an error.
func BodyFatReadingAgeDays(readingDate string, now time.Time) (int, bool) {
	d, err := time.Parse("2006-01-02", readingDate)
	if err != nil {
		return 0, false
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return int(today.Sub(d).Hours() / 24), true
}

const (
	BMRFormulaMifflin = "mifflin_st_jeor"
	BMRFormulaKatch   = "katch_mcardle"
)

type PlanTrend struct {
	// SlopePerWeek is a weight per week and therefore in PlanResponse.Unit.
	SlopePerWeek   float64 `json:"slopePerWeek"`
	HasData        bool    `json:"hasData"`
	ProjectedWeeks float64 `json:"projectedWeeks"`
	ProjectedDate  *string `json:"projectedDate"`
	Status         string  `json:"status"`
}

type SeriesPoint struct {
	Date    string   `json:"date"`
	Weight  float64  `json:"weight"`
	BodyFat *float64 `json:"bodyFat,omitempty"`
}

// PlanResponse is the fully-computed GET /plan payload.
//
// Every weight-valued field in it — currentWeight, series[].weight,
// composition.leanMass/fatMass, healthyRange.min/max, computed.ratePerWeek,
// computed.planCurve[].weight, trend.slopePerWeek and the echoed goal's
// weights — is in Unit. None of them is named after a unit, because none of
// them is always kilograms; Unit is the single place the payload says which
// unit it is in. See ConvertPlanResponseToDisplayUnit.
type PlanResponse struct {
	// Unit is "kg" or "lb": the unit every weight-valued field below is in.
	// AssemblePlan computes in kilograms and labels itself accordingly;
	// ConvertPlanResponseToDisplayUnit restamps it when it converts.
	Unit               string            `json:"unit"`
	Metrics            PlanMetrics       `json:"metrics"`
	CurrentWeight      *float64          `json:"currentWeight"`
	BMI                *float64          `json:"bmi"`
	BMICategory        *string           `json:"bmiCategory"`
	Composition        *BodyComposition  `json:"composition"`
	HealthyRange       *HealthyRange     `json:"healthyRange"`
	Goal               *model.WeightGoal `json:"goal"`
	Computed           *PlanComputed     `json:"computed"`
	Trend              *PlanTrend        `json:"trend"`
	CurrentCalorieGoal *int              `json:"currentCalorieGoal"`
	Series             []SeriesPoint     `json:"series"`
	Warnings           []PlanWarning     `json:"warnings"`
	Disclaimer         string            `json:"disclaimer"`

	// GoalReachedNow is an internal-only flag (not serialized): the handler
	// uses it to decide whether to mark the active goal achieved.
	GoalReachedNow bool `json:"-"`
}

// AssemblePlan computes the full plan payload from pre-gathered inputs. It
// performs no DB access and reads no wall-clock time (Now is injected), so it
// is fully unit-testable.
func AssemblePlan(in PlanInputs) PlanResponse {
	out := PlanResponse{
		// AssemblePlan's inputs are kilograms throughout (the handlers convert
		// on the way in), so the payload starts out honestly labelled kg. The
		// display-unit conversion restamps it.
		Unit: UnitKg,
		// Copied, not aliased. CurrentWeight is the one pointer in the payload
		// that ConvertPlanResponseToDisplayUnit writes through, and handing
		// back in.CurrentWeight would make that conversion reach backwards
		// into the caller's PlanInputs — assembling one plan twice and
		// converting either copy would then corrupt the other.
		CurrentWeight:      copyFloat(in.CurrentWeight),
		Goal:               in.Goal,
		CurrentCalorieGoal: in.CurrentCalGoal,
		Series:             make([]SeriesPoint, 0, len(in.Series)),
		Warnings:           []PlanWarning{},
		Disclaimer:         PlanDisclaimer,
		Metrics: PlanMetrics{
			HeightCm:      in.HeightCm,
			BirthYear:     in.BirthYear,
			Sex:           in.Sex,
			ActivityLevel: in.ActivityLevel,
			Complete:      in.HeightCm != nil && in.BirthYear != nil && in.Sex != nil && in.ActivityLevel != nil,
		},
	}

	for _, p := range in.Series {
		out.Series = append(out.Series, SeriesPoint{Date: p.Date.Format("2006-01-02"), Weight: p.Weight, BodyFat: p.BodyFat})
	}

	// baseWeight is the single weight everything downstream is anchored on: the
	// latest logged weight, or the goal's start weight when nothing has been
	// logged yet. It is resolved here, above the composition block, so the
	// lean/fat split shown to the user is derived from exactly the weight the
	// BMR is derived from. Computing them from two different weights is what let
	// the displayed lean mass disagree with the lean mass the budget came from.
	var baseWeight float64
	var haveBaseWeight bool
	switch {
	case in.CurrentWeight != nil:
		baseWeight, haveBaseWeight = *in.CurrentWeight, true
	case in.Goal != nil:
		baseWeight, haveBaseWeight = in.Goal.StartWeight, true
	}

	// Composition needs only a body-fat reading — no height, age or sex — so it
	// is derived before (and independently of) the metrics-complete gate below.
	// bodyFatFresh is the one place the recency window is decided; the BMR
	// branch further down consults it rather than re-deriving the rule.
	bodyFatFresh := false
	if r := in.CurrentBodyFat; r != nil {
		// Carry the percentage onto baseWeight, not onto the weight the reading
		// was taken at, so the split reported here is the split the BMR uses.
		compWeight := r.WeightKg
		if haveBaseWeight {
			compWeight = baseWeight
		}
		lean := LeanBodyMass(compWeight, r.Pct)
		if lean > 0 {
			ageDays, dated := BodyFatReadingAgeDays(r.Date, in.Now)
			// An unparseable date cannot be shown to be recent, so it is not
			// trusted to pick the formula.
			bodyFatFresh = dated && ageDays <= BodyFatRecencyDays
			comp := &BodyComposition{
				Date:       r.Date,
				BodyFatPct: r.Pct,
				LeanMass:   round1(lean),
				FatMass:    round1(FatMass(compWeight, r.Pct)),
				AgeDays:    ageDays,
				Stale:      !bodyFatFresh,
			}
			if in.Sex != nil {
				if cat := BodyFatCategory(Sex(*in.Sex), r.Pct); cat != "" {
					comp.Category = &cat
				}
			}
			out.Composition = comp
		}
	}

	if in.HeightCm != nil && in.CurrentWeight != nil {
		bmi := round1(BMI(*in.CurrentWeight, *in.HeightCm))
		cat := BMICategory(bmi)
		minKg, maxKg := HealthyWeightRange(*in.HeightCm)
		out.BMI = &bmi
		out.BMICategory = &cat
		out.HealthyRange = &HealthyRange{Min: round1(minKg), Max: round1(maxKg)}
	}

	goal := in.Goal
	if goal == nil {
		return out
	}

	dir := GoalDirection(goal.StartWeight, goal.TargetWeight)
	rate := goalRate(goal)

	// Trend only needs the goal's target/rate and the logged series — it does
	// not require the body-metrics profile, so it degrades gracefully even
	// when Metrics.Complete is false.
	trend := TrendAnalysis(in.Series, goal.TargetWeight, rate, 30, in.Now)
	pt := &PlanTrend{
		SlopePerWeek: trend.SlopeKgPerWeek, // kg here; converted with the rest below

		HasData:        trend.HasData,
		ProjectedWeeks: trend.ProjectedWeeks,
		Status:         trend.Status,
	}
	if trend.HasData && trend.ProjectedWeeks >= 0 && !math.IsInf(trend.ProjectedWeeks, 0) {
		d := in.Now.AddDate(0, 0, int(math.Round(trend.ProjectedWeeks*7))).Format("2006-01-02")
		pt.ProjectedDate = &d
	}
	out.Trend = pt

	if in.CurrentWeight != nil {
		out.GoalReachedNow = (dir == DirLoss && *in.CurrentWeight <= goal.TargetWeight) ||
			(dir == DirGain && *in.CurrentWeight >= goal.TargetWeight)
	}

	// A goal's rate can be non-finite (+Inf from RateForDate when a date-mode
	// goal's target_date collapses onto start_date, e.g. across a timezone
	// boundary) or <=0 (goalRate's "cannot be determined" sentinel). Either
	// way we can't safely derive BMR/TDEE/budget/ETA from it, so omit
	// Computed rather than let a non-finite value reach encoding/json.
	if !out.Metrics.Complete || math.IsInf(rate, 0) || math.IsNaN(rate) || rate <= 0 {
		return out
	}

	sex := Sex(*in.Sex)
	activity := ActivityLevel(*in.ActivityLevel)
	heightCm := *in.HeightCm
	ageYears := in.Now.Year() - *in.BirthYear

	// baseWeight was resolved above the composition block; reaching here implies
	// a non-nil goal, so it is always set.

	// A measured body fat beats an estimate from height/age/sex: Katch–McArdle
	// works off lean mass, which is what actually burns the calories. Anchor it
	// on baseWeight (not the reading's own weight) so the projection starts
	// where the plan does; the percentage is carried over on the assumption
	// that composition has not swung since it was measured — an assumption that
	// only holds for a recent reading, which is what bodyFatFresh enforces.
	// Outside BodyFatRecencyDays the reading is still reported (see
	// out.Composition) but Mifflin-St Jeor drives the budget, because a stale
	// percentage dressed up as Katch-McArdle is a wrong answer claiming to be
	// the more accurate one.
	bmrModel := MifflinModel(sex, heightCm, ageYears)
	formula := BMRFormulaMifflin
	if r := in.CurrentBodyFat; r != nil && bodyFatFresh {
		bmrModel = KatchMcArdleModel(baseWeight, r.Pct)
		formula = BMRFormulaKatch
	}

	bmr := bmrModel(baseWeight)
	tdee := TDEE(bmr, activity)
	floor := CalorieFloor(sex)
	budget, clamped := RecommendedBudget(tdee, rate, dir, floor)
	etaWeeks := ETAWeeks(baseWeight, goal.TargetWeight, rate)

	var etaDate *string
	if !math.IsInf(etaWeeks, 0) && !math.IsNaN(etaWeeks) {
		d := in.Now.AddDate(0, 0, int(math.Round(etaWeeks*7))).Format("2006-01-02")
		etaDate = &d
	}

	curve := AdaptivePlanCurve(baseWeight, goal.TargetWeight, float64(budget), bmrModel, activity, 0)

	out.Computed = &PlanComputed{
		BMR:           round1(bmr),
		TDEE:          round1(tdee),
		BudgetKcal:    budget,
		BudgetClamped: clamped,
		RatePerWeek:   rate, // kg/week here; converted with the rest of the payload
		ETAWeeks:      etaWeeks,
		ETADate:       etaDate,
		PlanCurve:     curve,
		BMRFormula:    formula,
	}

	if clamped {
		out.Warnings = append(out.Warnings, PlanWarning{
			Code:    "budget_clamped",
			Message: "Your recommended calorie budget was raised to the safe minimum for your profile.",
		})
	}
	if RateSharePerWeek(rate, baseWeight) > 0.01 {
		out.Warnings = append(out.Warnings, PlanWarning{
			Code:    "aggressive_rate",
			Message: "Your target pace is faster than 1% of body weight per week, which may be unsafe or unsustainable.",
		})
	}
	targetBMI := BMI(goal.TargetWeight, heightCm)
	if targetBMI < 18.5 {
		out.Warnings = append(out.Warnings, PlanWarning{
			Code:    "target_underweight",
			Message: "Your target weight falls in the underweight BMI range.",
		})
	}
	if dir == DirGain && targetBMI >= 30 {
		out.Warnings = append(out.Warnings, PlanWarning{
			Code:    "target_obese",
			Message: "Your target weight falls in the obese BMI range.",
		})
	}

	return out
}

// copyFloat returns a pointer to a copy of *p, or nil. It exists so the
// assembled payload owns its own weights: everything else in PlanResponse that
// the unit conversion touches is a value or a freshly built struct, and this
// keeps CurrentWeight from being the exception.
func copyFloat(p *float64) *float64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// goalRate returns the goal's pace as a positive kg/week magnitude, from
// either the explicit rate (pace_mode=rate) or derived from the target date
// (pace_mode=date). Returns 0 if it cannot be determined.
func goalRate(g *model.WeightGoal) float64 {
	switch g.PaceMode {
	case "rate":
		if g.RateKgPerWeek != nil {
			return *g.RateKgPerWeek
		}
	case "date":
		if g.TargetDate != nil {
			startDate, err1 := time.Parse("2006-01-02", g.StartDate)
			targetDate, err2 := time.Parse("2006-01-02", *g.TargetDate)
			if err1 == nil && err2 == nil {
				return RateForDate(g.StartWeight, g.TargetWeight, startDate, targetDate)
			}
		}
	}
	return 0
}
