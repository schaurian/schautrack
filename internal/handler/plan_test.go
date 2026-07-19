package handler

import (
	"encoding/json"
	"testing"
	"time"

	"schautrack/internal/model"
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

func TestValidateTargetWeight(t *testing.T) {
	if !validateTargetWeight(70) {
		t.Error("70 should be valid")
	}
	if validateTargetWeight(0) {
		t.Error("0 should be invalid")
	}
	if validateTargetWeight(-5) {
		t.Error("-5 should be invalid")
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
}

func TestValidateTargetDate(t *testing.T) {
	now := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	future, past, today, malformed := "2026-08-01", "2026-07-01", "2026-07-19", "not-a-date"

	if !validateTargetDate("rate", nil, now) {
		t.Error("target_date is not required in rate mode")
	}
	if !validateTargetDate("date", &future, now) {
		t.Error("future date should be valid in date mode")
	}
	if validateTargetDate("date", nil, now) {
		t.Error("nil date should be invalid in date mode")
	}
	if validateTargetDate("date", &past, now) {
		t.Error("past date should be invalid in date mode")
	}
	if validateTargetDate("date", &today, now) {
		t.Error("today should be invalid — target date must be strictly in the future")
	}
	if validateTargetDate("date", &malformed, now) {
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
