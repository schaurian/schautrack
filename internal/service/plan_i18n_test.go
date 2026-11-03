package service

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"schautrack/internal/model"
)

// The plan page renders its disclaimer and warnings from the client catalog so
// they follow the UI language; the API still carries the English text. These
// pin the two together: a reworded server string, or a new warning code the
// catalog does not name, fails here instead of silently drifting in the UI.

type planCatalog struct {
	Plan struct {
		Disclaimer string            `json:"disclaimer"`
		Warnings   map[string]string `json:"warnings"`
	} `json:"plan"`
}

func loadEnDashboardCatalog(t *testing.T) planCatalog {
	t.Helper()
	raw, err := os.ReadFile("../../client/src/i18n/locales/en/dashboard.json")
	if err != nil {
		t.Fatalf("read en catalog: %v", err)
	}
	var c planCatalog
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse en catalog: %v", err)
	}
	return c
}

func TestPlanDisclaimerMatchesClientCatalog(t *testing.T) {
	c := loadEnDashboardCatalog(t)
	if c.Plan.Disclaimer != PlanDisclaimer {
		t.Fatalf("client plan.disclaimer differs from PlanDisclaimer:\n client: %q\n server: %q", c.Plan.Disclaimer, PlanDisclaimer)
	}
}

// warningScenarios are real AssemblePlan inputs that between them raise every
// warning the planner knows. The codes and messages under test are whatever
// AssemblePlan actually returns, so how a warning is written in the source (a
// literal, a constant, a Sprintf) cannot hide it from this check.
func warningScenarios() map[string]PlanInputs {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	person := func(age int, sex, activity string, height, current float64, goal *model.WeightGoal) PlanInputs {
		by := now.Year() - age
		return PlanInputs{
			CurrentWeight: f64(current), HeightCm: f64(height), BirthYear: &by,
			Sex: &sex, ActivityLevel: &activity, Goal: goal, Now: now,
		}
	}
	return map[string]PlanInputs{
		// 2 kg/week on a 60 kg person: budget clamps and the pace is > 1%/week.
		"aggressive loss": person(25, "female", "sedentary", 160, 60, &model.WeightGoal{
			ID: 1, UserID: 1, StartWeight: 60, StartDate: "2026-07-01",
			TargetWeight: 50, PaceMode: "rate", RateKgPerWeek: f64(2.0), Status: "active",
		}),
		// Target BMI 15.6.
		"underweight target": person(28, "female", "light", 170, 70, &model.WeightGoal{
			ID: 2, UserID: 1, StartWeight: 70, StartDate: "2026-07-01",
			TargetWeight: 45, PaceMode: "rate", RateKgPerWeek: f64(0.3), Status: "active",
		}),
		// Gaining to target BMI 31.1.
		"obese gain target": person(30, "male", "moderate", 170, 70, &model.WeightGoal{
			ID: 3, UserID: 1, StartWeight: 70, StartDate: "2026-07-01",
			TargetWeight: 90, PaceMode: "rate", RateKgPerWeek: f64(0.3), Status: "active",
		}),
	}
}

func TestPlanWarningCodesMatchClientCatalog(t *testing.T) {
	c := loadEnDashboardCatalog(t)
	emitted := map[string]string{}
	for name, in := range warningScenarios() {
		for _, w := range AssemblePlan(in).Warnings {
			if prev, seen := emitted[w.Code]; seen && prev != w.Message {
				t.Errorf("%s: warning %q has two messages: %q and %q", name, w.Code, prev, w.Message)
			}
			emitted[w.Code] = w.Message
		}
	}
	for code, msg := range emitted {
		got, ok := c.Plan.Warnings[code]
		if !ok {
			t.Errorf("warning code %q has no client translation key plan.warnings.%s", code, code)
			continue
		}
		if got != msg {
			t.Errorf("plan.warnings.%s = %q, server message = %q", code, got, msg)
		}
	}
	// The other direction: every catalogued warning must still be raised by
	// one of the scenarios, so a code the server renamed (or a scenario that
	// stopped triggering its warning) cannot leave this test checking nothing.
	for code := range c.Plan.Warnings {
		if _, ok := emitted[code]; !ok {
			t.Errorf("plan.warnings.%s is catalogued but no scenario raised it (emitted: %v)", code, emitted)
		}
	}
}
