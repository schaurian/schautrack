package service

import (
	"math"
	"time"
)

type Sex string

const (
	SexMale   Sex = "male"
	SexFemale Sex = "female"
	SexOther  Sex = "other"
)

type ActivityLevel string

const (
	ActivitySedentary  ActivityLevel = "sedentary"
	ActivityLight      ActivityLevel = "light"
	ActivityModerate   ActivityLevel = "moderate"
	ActivityActive     ActivityLevel = "active"
	ActivityVeryActive ActivityLevel = "very_active"
)

type Direction string

const (
	DirLoss     Direction = "loss"
	DirGain     Direction = "gain"
	DirMaintain Direction = "maintain"
)

const KcalPerKg = 7700.0

var activityFactors = map[ActivityLevel]float64{
	ActivitySedentary: 1.2, ActivityLight: 1.375, ActivityModerate: 1.55,
	ActivityActive: 1.725, ActivityVeryActive: 1.9,
}

func ActivityFactor(a ActivityLevel) float64 { return activityFactors[a] } // 0 if unknown

// BMR uses Mifflin–St Jeor. Returns 0 if any input is non-positive.
func BMR(sex Sex, weightKg, heightCm float64, ageYears int) float64 {
	if weightKg <= 0 || heightCm <= 0 || ageYears <= 0 {
		return 0
	}
	c := -78.0 // "other" neutral average
	switch sex {
	case SexMale:
		c = 5
	case SexFemale:
		c = -161
	}
	return 10*weightKg + 6.25*heightCm - 5*float64(ageYears) + c
}

func TDEE(bmr float64, a ActivityLevel) float64 {
	f := ActivityFactor(a)
	if f == 0 {
		f = 1.2 // conservative default when unknown
	}
	return bmr * f
}

func DailyDeficitForRate(rateKgPerWeek float64) float64 {
	return math.Abs(rateKgPerWeek) * KcalPerKg / 7
}

func GoalDirection(startW, targetW float64) Direction {
	switch {
	case targetW < startW:
		return DirLoss
	case targetW > startW:
		return DirGain
	default:
		return DirMaintain
	}
}

func CalorieFloor(sex Sex) float64 {
	switch sex {
	case SexMale:
		return 1500
	case SexFemale:
		return 1200
	case SexOther:
		return 1300
	default:
		return 1200
	}
}

// RecommendedBudget returns the daily kcal target and whether it was clamped to floor.
func RecommendedBudget(tdee, rateKgPerWeek float64, dir Direction, floor float64) (int, bool) {
	delta := DailyDeficitForRate(rateKgPerWeek)
	var budget float64
	switch dir {
	case DirGain:
		budget = tdee + delta
	case DirMaintain:
		budget = tdee
	default:
		budget = tdee - delta
	}
	clamped := false
	if budget < floor {
		budget = floor
		clamped = true
	}
	return int(math.Round(budget)), clamped
}

func RateForDate(startW, targetW float64, startDate, targetDate time.Time) float64 {
	weeks := targetDate.Sub(startDate).Hours() / (24 * 7)
	if weeks <= 0 {
		return math.Inf(1)
	}
	return math.Abs(startW-targetW) / weeks
}

func ETAWeeks(currentW, targetW, rateKgPerWeek float64) float64 {
	if rateKgPerWeek <= 0 {
		return math.Inf(1)
	}
	return math.Abs(currentW-targetW) / rateKgPerWeek
}

func BMI(weightKg, heightCm float64) float64 {
	if heightCm <= 0 {
		return 0
	}
	m := heightCm / 100
	return weightKg / (m * m)
}

func BMICategory(bmi float64) string {
	switch {
	case bmi < 18.5:
		return "underweight"
	case bmi < 25:
		return "normal"
	case bmi < 30:
		return "overweight"
	default:
		return "obese"
	}
}

func HealthyWeightRange(heightCm float64) (float64, float64) {
	m := heightCm / 100
	return 18.5 * m * m, 24.9 * m * m
}

func RateSharePerWeek(rateKgPerWeek, currentW float64) float64 {
	if currentW <= 0 {
		return 0
	}
	return math.Abs(rateKgPerWeek) / currentW
}

type CurvePoint struct {
	Week   int     `json:"week"`
	Weight float64 `json:"weight"`
}

// AdaptivePlanCurve simulates weekly weight at a fixed budget, recomputing TDEE
// as weight changes (realistic decelerating curve). Stops at target or maxWeeks.
func AdaptivePlanCurve(startW, targetW, budgetKcal float64, sex Sex, heightCm float64, ageYears int, a ActivityLevel, maxWeeks int) []CurvePoint {
	if maxWeeks <= 0 {
		maxWeeks = 160
	}
	dir := GoalDirection(startW, targetW)
	pts := []CurvePoint{{Week: 0, Weight: round1(startW)}}
	w := startW
	for wk := 1; wk <= maxWeeks; wk++ {
		tdee := TDEE(BMR(sex, w, heightCm, ageYears), a)
		dailyDelta := budgetKcal - tdee                 // <0 => losing
		weeklyKg := dailyDelta * 7 / KcalPerKg          // signed kg change
		w += weeklyKg
		if w < 30 {
			w = 30
		}
		pts = append(pts, CurvePoint{Week: wk, Weight: round1(w)})
		if (dir == DirLoss && w <= targetW) || (dir == DirGain && w >= targetW) {
			break
		}
		if math.Abs(weeklyKg) < 0.01 { // plateau — won't reach target
			break
		}
	}
	return pts
}

type WeightPoint struct {
	Date   time.Time
	Weight float64
}

type Trend struct {
	SlopeKgPerWeek float64 `json:"slope_kg_per_week"`
	HasData        bool    `json:"has_data"`
	ProjectedWeeks float64 `json:"projected_weeks"` // to target; -1 if not projectable
	Status         string  `json:"status"`
}

// TrendAnalysis fits a least-squares line over points within windowDays of now.
func TrendAnalysis(points []WeightPoint, targetW, planRateKgPerWeek float64, windowDays int, now time.Time) Trend {
	cutoff := now.AddDate(0, 0, -windowDays)
	var xs, ys []float64
	var t0 time.Time
	for _, p := range points {
		if p.Date.Before(cutoff) {
			continue
		}
		if t0.IsZero() {
			t0 = p.Date
		}
		xs = append(xs, p.Date.Sub(t0).Hours()/24) // days
		ys = append(ys, p.Weight)
	}
	if len(xs) < 2 || xs[len(xs)-1]-xs[0] < 7 {
		return Trend{HasData: false, ProjectedWeeks: -1, Status: "insufficient_data"}
	}
	slopePerDay := leastSquaresSlope(xs, ys)
	slopePerWeek := slopePerDay * 7
	tr := Trend{SlopeKgPerWeek: slopePerWeek, HasData: true, ProjectedWeeks: -1}

	dir := GoalDirection(ys[len(ys)-1], targetW)
	progressing := (dir == DirLoss && slopePerWeek < 0) || (dir == DirGain && slopePerWeek > 0)
	switch {
	case math.Abs(slopePerWeek) < 0.05:
		tr.Status = "stalled"
	case !progressing:
		tr.Status = "wrong_direction"
	default:
		tr.ProjectedWeeks = math.Abs(ys[len(ys)-1]-targetW) / math.Abs(slopePerWeek)
		ratio := math.Abs(slopePerWeek) / math.Max(planRateKgPerWeek, 1e-9)
		switch {
		case ratio >= 1.1:
			tr.Status = "ahead"
		case ratio >= 0.85:
			tr.Status = "on_track"
		default:
			tr.Status = "behind"
		}
	}
	return tr
}

func leastSquaresSlope(xs, ys []float64) float64 {
	n := float64(len(xs))
	var sx, sy, sxx, sxy float64
	for i := range xs {
		sx += xs[i]
		sy += ys[i]
		sxx += xs[i] * xs[i]
		sxy += xs[i] * ys[i]
	}
	den := n*sxx - sx*sx
	if den == 0 {
		return 0
	}
	return (n*sxy - sx*sy) / den
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

type PlanWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
