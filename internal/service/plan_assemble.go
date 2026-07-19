package service

import (
	"math"
	"time"

	"schautrack/internal/model"
)

// PlanDisclaimer is surfaced verbatim to the client alongside every plan payload.
const PlanDisclaimer = "This plan is an estimate based on standard formulas (Mifflin-St Jeor) and general activity guidelines. " +
	"It is not medical advice — consult a healthcare professional before starting any weight-loss or weight-gain program, " +
	"especially if you have underlying health conditions."

// PlanInputs is everything AssemblePlan needs, gathered by the handler from the
// DB. AssemblePlan itself performs no I/O and does not read the wall clock.
type PlanInputs struct {
	CurrentWeight  *float64 // nil if no weight logged
	HeightCm       *float64
	BirthYear      *int
	Sex            *string
	ActivityLevel  *string
	Goal           *model.WeightGoal // nil if none active
	Series         []WeightPoint
	CurrentCalGoal *int
	Now            time.Time
}

type PlanMetrics struct {
	HeightCm      *float64 `json:"heightCm"`
	BirthYear     *int     `json:"birthYear"`
	Sex           *string  `json:"sex"`
	ActivityLevel *string  `json:"activityLevel"`
	Complete      bool     `json:"complete"`
}

type HealthyRange struct {
	MinKg float64 `json:"minKg"`
	MaxKg float64 `json:"maxKg"`
}

type PlanComputed struct {
	BMR           float64      `json:"bmr"`
	TDEE          float64      `json:"tdee"`
	BudgetKcal    int          `json:"budgetKcal"`
	BudgetClamped bool         `json:"budgetClamped"`
	RateKgPerWeek float64      `json:"rateKgPerWeek"`
	ETAWeeks      float64      `json:"etaWeeks"`
	ETADate       *string      `json:"etaDate"`
	PlanCurve     []CurvePoint `json:"planCurve"`
}

type PlanTrend struct {
	SlopeKgPerWeek float64 `json:"slopeKgPerWeek"`
	HasData        bool    `json:"hasData"`
	ProjectedWeeks float64 `json:"projectedWeeks"`
	ProjectedDate  *string `json:"projectedDate"`
	Status         string  `json:"status"`
}

type SeriesPoint struct {
	Date   string  `json:"date"`
	Weight float64 `json:"weight"`
}

// PlanResponse is the fully-computed GET /plan payload.
type PlanResponse struct {
	Metrics            PlanMetrics       `json:"metrics"`
	CurrentWeight      *float64          `json:"currentWeight"`
	BMI                *float64          `json:"bmi"`
	BMICategory        *string           `json:"bmiCategory"`
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
		CurrentWeight:      in.CurrentWeight,
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
		out.Series = append(out.Series, SeriesPoint{Date: p.Date.Format("2006-01-02"), Weight: p.Weight})
	}

	if in.HeightCm != nil && in.CurrentWeight != nil {
		bmi := round1(BMI(*in.CurrentWeight, *in.HeightCm))
		cat := BMICategory(bmi)
		minKg, maxKg := HealthyWeightRange(*in.HeightCm)
		out.BMI = &bmi
		out.BMICategory = &cat
		out.HealthyRange = &HealthyRange{MinKg: round1(minKg), MaxKg: round1(maxKg)}
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
		SlopeKgPerWeek: trend.SlopeKgPerWeek,
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

	if !out.Metrics.Complete {
		return out
	}

	sex := Sex(*in.Sex)
	activity := ActivityLevel(*in.ActivityLevel)
	heightCm := *in.HeightCm
	ageYears := in.Now.Year() - *in.BirthYear

	baseWeight := goal.StartWeight
	if in.CurrentWeight != nil {
		baseWeight = *in.CurrentWeight
	}

	bmr := BMR(sex, baseWeight, heightCm, ageYears)
	tdee := TDEE(bmr, activity)
	floor := CalorieFloor(sex)
	budget, clamped := RecommendedBudget(tdee, rate, dir, floor)
	etaWeeks := ETAWeeks(baseWeight, goal.TargetWeight, rate)

	var etaDate *string
	if !math.IsInf(etaWeeks, 0) && !math.IsNaN(etaWeeks) {
		d := in.Now.AddDate(0, 0, int(math.Round(etaWeeks*7))).Format("2006-01-02")
		etaDate = &d
	}

	curve := AdaptivePlanCurve(baseWeight, goal.TargetWeight, float64(budget), sex, heightCm, ageYears, activity, 0)

	out.Computed = &PlanComputed{
		BMR:           round1(bmr),
		TDEE:          round1(tdee),
		BudgetKcal:    budget,
		BudgetClamped: clamped,
		RateKgPerWeek: rate,
		ETAWeeks:      etaWeeks,
		ETADate:       etaDate,
		PlanCurve:     curve,
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
