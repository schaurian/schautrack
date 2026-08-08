package handler

import (
	"encoding/json"
	"math"
	"testing"

	"schautrack/internal/model"
	"schautrack/internal/service"
)

func TestValidateHeightCm(t *testing.T) {
	h50, h300, h49, h301 := 50.0, 300.0, 49.9, 300.1
	tests := []struct {
		name string
		val  *float64
		want bool
	}{
		{"nil is valid (optional)", nil, true},
		{"lower bound", &h50, true},
		{"upper bound", &h300, true},
		{"below lower bound", &h49, false},
		{"above upper bound", &h301, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateHeightCm(tt.val); got != tt.want {
				t.Errorf("validateHeightCm(%v) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestValidateBirthYear(t *testing.T) {
	y1899, y1900, yTooYoung, yOk := 1899, 1900, 2020, 1990
	currentYear := 2026
	tests := []struct {
		name string
		val  *int
		want bool
	}{
		{"nil is valid (optional)", nil, true},
		{"lower bound", &y1900, true},
		{"below lower bound", &y1899, false},
		{"too young (< 10yo)", &yTooYoung, false},
		{"reasonable adult", &yOk, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateBirthYear(tt.val, currentYear); got != tt.want {
				t.Errorf("validateBirthYear(%v, %d) = %v, want %v", tt.val, currentYear, got, tt.want)
			}
		})
	}
}

func TestValidateSex(t *testing.T) {
	male, bogus := "male", "robot"
	tests := []struct {
		name string
		val  *string
		want bool
	}{
		{"nil valid", nil, true},
		{"male valid", &male, true},
		{"bogus invalid", &bogus, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateSex(tt.val); got != tt.want {
				t.Errorf("validateSex(%v) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

func TestValidateActivityLevel(t *testing.T) {
	moderate, bogus := "moderate", "lazy"
	tests := []struct {
		name string
		val  *string
		want bool
	}{
		{"nil valid", nil, true},
		{"moderate valid", &moderate, true},
		{"bogus invalid", &bogus, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateActivityLevel(tt.val); got != tt.want {
				t.Errorf("validateActivityLevel(%v) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

// targetWeightColumnMax is the largest value the weight_goals.target_weight
// NUMERIC(6,2) column can hold (internal/database/migrations.go). Anything the
// validator accepts must fit, or the INSERT overflows and the caller gets a 500
// instead of a 400.
const targetWeightColumnMax = 9999.99

// fitsTargetWeightColumn reports whether w survives an INSERT into
// NUMERIC(6,2). Postgres rounds to two decimals on store, so the check is
// against the rounded value; NaN and ±Inf never fit.
func fitsTargetWeightColumn(w float64) bool {
	if math.IsNaN(w) || math.IsInf(w, 0) {
		return false
	}
	return math.Abs(math.Round(w*100)/100) <= targetWeightColumnMax
}

func TestValidateTargetWeight(t *testing.T) {
	tests := []struct {
		name string
		val  float64
		want bool
	}{
		{"zero", 0, false},
		{"negative", -5, false},
		{"NaN", math.NaN(), false},
		{"positive infinity", math.Inf(1), false},
		{"negative infinity", math.Inf(-1), false},
		{"tiny but positive", 0.001, true},
		{"one", 1, true},
		{"typical", 70, true},
		{"ParseWeight cap", service.MaxWeight, true},
		{"just over the ParseWeight cap", service.MaxWeight + 1, false},
		{"column max", targetWeightColumnMax, false},
		{"column max plus one", 10000, false},
		{"absurdly large", 1e9, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateTargetWeight(tt.val); got != tt.want {
				t.Errorf("validateTargetWeight(%v) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

// TestValidateTargetWeightFitsColumn pins the invariant validateRateKgPerWeek
// already holds for its own column: every value the validator accepts must be
// storable in target_weight NUMERIC(6,2). Without an upper bound in the
// validator, {"target_weight": 100000} passed here and 500d on INSERT.
func TestValidateTargetWeightFitsColumn(t *testing.T) {
	candidates := []float64{
		math.NaN(), math.Inf(1), math.Inf(-1),
		-1e9, -1, 0,
		0.001, 0.005, 1, 70, 999.994,
		service.MaxWeight - 0.01, service.MaxWeight, service.MaxWeight + 0.01,
		1501, 9999.99, 9999.995, 10000, 1e6, 1e9, math.MaxFloat64,
	}
	for f := 0.5; f < 1e12; f *= 3 {
		candidates = append(candidates, f)
	}
	for _, w := range candidates {
		if validateTargetWeight(w) && !fitsTargetWeightColumn(w) {
			t.Errorf("validateTargetWeight(%v) accepted a value that does not fit NUMERIC(6,2)", w)
		}
	}
}

func TestValidatePaceMode(t *testing.T) {
	if !validatePaceMode("rate") {
		t.Error("rate should be valid")
	}
	if !validatePaceMode("date") {
		t.Error("date should be valid")
	}
	if validatePaceMode("asap") {
		t.Error("asap should be invalid")
	}
	if validatePaceMode("") {
		t.Error("empty string should be invalid")
	}
}

func TestValidateRateKgPerWeek(t *testing.T) {
	rate, zero, neg := 0.5, 0.0, -0.5

	if !validateRateKgPerWeek("date", nil) {
		t.Error("rate is not required in date mode")
	}
	if !validateRateKgPerWeek("rate", &rate) {
		t.Error("positive rate should be valid in rate mode")
	}
	if validateRateKgPerWeek("rate", nil) {
		t.Error("nil rate should be invalid in rate mode")
	}
	if validateRateKgPerWeek("rate", &zero) {
		t.Error("zero rate should be invalid in rate mode")
	}
	if validateRateKgPerWeek("rate", &neg) {
		t.Error("negative rate should be invalid in rate mode")
	}
	over := 100.0
	if validateRateKgPerWeek("rate", &over) {
		t.Error("rate over the NUMERIC(4,2) column max should be invalid in rate mode")
	}
	max := 99.0
	if !validateRateKgPerWeek("rate", &max) {
		t.Error("rate at the accepted upper bound should be valid in rate mode")
	}
}

func TestValidateTargetDate(t *testing.T) {
	// todayStr stands in for the tz-aware "today" the caller computes via
	// service.FormatDateInTz — validateTargetDate itself takes a plain date
	// string so it stays pure/testable without a timezone dependency.
	todayStr := "2026-07-19"
	future, past, today, malformed := "2026-08-01", "2026-07-01", "2026-07-19", "not-a-date"

	if !validateTargetDate("rate", nil, todayStr) {
		t.Error("target_date is not required in rate mode")
	}
	if !validateTargetDate("date", &future, todayStr) {
		t.Error("future date should be valid in date mode")
	}
	if validateTargetDate("date", nil, todayStr) {
		t.Error("nil date should be invalid in date mode")
	}
	if validateTargetDate("date", &past, todayStr) {
		t.Error("past date should be invalid in date mode")
	}
	if validateTargetDate("date", &today, todayStr) {
		t.Error("today should be invalid — target date must be strictly in the future")
	}
	if validateTargetDate("date", &malformed, todayStr) {
		t.Error("malformed date should be invalid")
	}
}

func TestCurrentCalorieGoal(t *testing.T) {
	dailyGoal := 2000

	t.Run("falls back to daily_goal when macro_goals has no calories key", func(t *testing.T) {
		u := &model.User{DailyGoal: &dailyGoal, MacroGoals: json.RawMessage(`{}`)}
		got := currentCalorieGoal(u)
		if got == nil || *got != dailyGoal {
			t.Errorf("currentCalorieGoal() = %v, want %d", got, dailyGoal)
		}
	})

	t.Run("prefers macro_goals.calories over daily_goal", func(t *testing.T) {
		u := &model.User{DailyGoal: &dailyGoal, MacroGoals: json.RawMessage(`{"calories": 2500}`)}
		got := currentCalorieGoal(u)
		if got == nil || *got != 2500 {
			t.Errorf("currentCalorieGoal() = %v, want 2500", got)
		}
	})

	t.Run("nil macro_goals and nil daily_goal returns nil", func(t *testing.T) {
		u := &model.User{MacroGoals: json.RawMessage(`null`)}
		if got := currentCalorieGoal(u); got != nil {
			t.Errorf("currentCalorieGoal() = %v, want nil", got)
		}
	})
}
