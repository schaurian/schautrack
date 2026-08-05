package service

// Body composition — everything derived from a weight plus a body-fat
// percentage. Kept apart from plan.go, which owns the energy/goal math, so the
// two concepts stay independently readable and testable.

// LeanBodyMass returns fat-free mass in kg. Returns 0 for inputs outside the
// range ParseBodyFat accepts, so a bad value can never produce a plausible-
// looking BMR downstream.
func LeanBodyMass(weightKg, bodyFatPct float64) float64 {
	if weightKg <= 0 || bodyFatPct <= 0 || bodyFatPct >= 100 {
		return 0
	}
	return weightKg * (1 - bodyFatPct/100)
}

// FatMass returns fat mass in kg, on the same guard as LeanBodyMass.
func FatMass(weightKg, bodyFatPct float64) float64 {
	if weightKg <= 0 || bodyFatPct <= 0 || bodyFatPct >= 100 {
		return 0
	}
	return weightKg * bodyFatPct / 100
}

// BMRKatchMcArdle estimates basal metabolic rate from lean mass alone:
// 370 + 21.6 × LBM. Unlike Mifflin–St Jeor it needs no sex, height or age,
// and it is the more accurate estimator once body composition is known —
// two people at the same weight but 15% vs 35% body fat have materially
// different maintenance needs, which a total-mass formula cannot see.
func BMRKatchMcArdle(leanMassKg float64) float64 {
	if leanMassKg <= 0 {
		return 0
	}
	return 370 + 21.6*leanMassKg
}

// bodyFatBands holds the lower bound of the athletic, fitness, average and
// obese categories, per the American Council on Exercise. Anything below the
// first bound is "essential" fat. The "other" row is the male/female midpoint,
// matching how BMR averages the sex constant and how CalorieFloor picks a
// middle value when sex is "other".
var bodyFatBands = map[Sex][4]float64{
	SexMale:   {6, 14, 18, 25},
	SexFemale: {14, 21, 25, 32},
	SexOther:  {10, 17.5, 21.5, 28.5},
}

// BodyFatCategory classifies a body-fat percentage for a sex. It returns ""
// when the sex is unknown (the bands genuinely differ by sex, so guessing
// would be worse than saying nothing) or the percentage is out of range —
// callers omit the label rather than showing a wrong one.
func BodyFatCategory(sex Sex, bodyFatPct float64) string {
	bands, ok := bodyFatBands[sex]
	if !ok || bodyFatPct <= 0 || bodyFatPct >= 100 {
		return ""
	}
	switch {
	case bodyFatPct < bands[0]:
		return "essential"
	case bodyFatPct < bands[1]:
		return "athletic"
	case bodyFatPct < bands[2]:
		return "fitness"
	case bodyFatPct < bands[3]:
		return "average"
	default:
		return "obese"
	}
}

// BMRModel returns the BMR to assume at a given projected body weight. It lets
// AdaptivePlanCurve simulate forward without knowing which formula produced the
// number — the two implementations below are interchangeable at every call site.
type BMRModel func(weightKg float64) float64

// MifflinModel is the total-mass model: BMR falls by 10 kcal for every kg lost.
func MifflinModel(sex Sex, heightCm float64, ageYears int) BMRModel {
	return func(weightKg float64) float64 {
		return BMR(sex, weightKg, heightCm, ageYears)
	}
}

// LeanShareOfWeightChange is the fraction of any weight change assumed to come
// from lean tissue rather than fat — the standard 75/25 split for a moderate
// deficit. It is what makes the Katch–McArdle projection decelerate at all:
// hold lean mass perfectly constant and BMR never moves, which would project a
// straight line no real body follows.
const LeanShareOfWeightChange = 0.25

// KatchMcArdleModel is the lean-mass model, anchored on a measured body-fat
// percentage at startWeightKg. As simulated weight moves away from that anchor,
// lean mass follows it at LeanShareOfWeightChange, so BMR falls by ~5.4 kcal
// per kg lost — roughly half of Mifflin's 10, which is exactly the point: a
// deficit that spares lean mass spares the metabolism with it.
//
// Falls back to a constant zero BMR for unusable inputs; callers treat a zero
// BMR the same way they already do for Mifflin.
func KatchMcArdleModel(startWeightKg, bodyFatPct float64) BMRModel {
	lean0 := LeanBodyMass(startWeightKg, bodyFatPct)
	return func(weightKg float64) float64 {
		lean := lean0 + LeanShareOfWeightChange*(weightKg-startWeightKg)
		return BMRKatchMcArdle(lean)
	}
}
