package service

import (
	"encoding/json"
	"testing"
)

func TestLinkUserAsMacroUser(t *testing.T) {
	tests := []struct {
		name          string
		lu            LinkUser
		wantGoal      *int
		wantThreshold int
	}{
		{
			"with goals and threshold",
			LinkUser{
				DailyGoal:     intPtr(2000),
				GoalThreshold: 15,
				MacrosEnabled: json.RawMessage(`{"protein":true,"carbs":false}`),
				MacroGoals:    json.RawMessage(`{"protein":150,"calories":2000}`),
			},
			intPtr(2000),
			15,
		},
		{
			"empty JSON objects",
			LinkUser{
				MacrosEnabled: json.RawMessage(`{}`),
				MacroGoals:    json.RawMessage(`{}`),
				GoalThreshold: 10,
			},
			nil,
			10,
		},
		{
			"nil JSON fields default gracefully",
			LinkUser{
				MacrosEnabled: nil,
				MacroGoals:    nil,
				GoalThreshold: 10,
			},
			nil,
			10,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mu := tt.lu.AsMacroUser()

			if mu.GoalThreshold != tt.wantThreshold {
				t.Errorf("GoalThreshold = %d, want %d", mu.GoalThreshold, tt.wantThreshold)
			}
			if (mu.DailyGoal == nil) != (tt.wantGoal == nil) {
				t.Errorf("DailyGoal = %v, want %v", mu.DailyGoal, tt.wantGoal)
			} else if mu.DailyGoal != nil && *mu.DailyGoal != *tt.wantGoal {
				t.Errorf("DailyGoal = %d, want %d", *mu.DailyGoal, *tt.wantGoal)
			}

			// MacrosEnabled and MacroGoals should be populated maps (not nil)
			if mu.MacrosEnabled == nil {
				t.Error("MacrosEnabled should not be nil")
			}
			if mu.MacroGoals == nil {
				t.Error("MacroGoals should not be nil")
			}
		})
	}
}

func TestLinkUserAsMacroUserEnabledMacros(t *testing.T) {
	lu := LinkUser{
		MacrosEnabled: json.RawMessage(`{"protein":true,"carbs":true,"fat":false}`),
		MacroGoals:    json.RawMessage(`{"protein":150,"carbs":200}`),
		GoalThreshold: 10,
	}
	mu := lu.AsMacroUser()
	enabled := GetEnabledMacros(mu)

	// Should include protein and carbs, not fat
	if len(enabled) != 2 {
		t.Fatalf("GetEnabledMacros() returned %d macros, want 2: %v", len(enabled), enabled)
	}
	if enabled[0] != "protein" || enabled[1] != "carbs" {
		t.Errorf("GetEnabledMacros() = %v, want [protein carbs]", enabled)
	}
}

func TestLinkStateDefaults(t *testing.T) {
	state := LinkState{Incoming: []LinkRequest{}, Outgoing: []LinkRequest{}}
	if len(state.Incoming) != 0 {
		t.Errorf("Incoming should be empty, got %d", len(state.Incoming))
	}
	if len(state.Outgoing) != 0 {
		t.Errorf("Outgoing should be empty, got %d", len(state.Outgoing))
	}
}
