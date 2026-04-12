package service

import (
	"testing"
)

func mu(macrosEnabled map[string]any, macroGoals map[string]any) MacroUser {
	if macrosEnabled == nil {
		macrosEnabled = map[string]any{}
	}
	if macroGoals == nil {
		macroGoals = map[string]any{}
	}
	return MacroUser{MacrosEnabled: macrosEnabled, MacroGoals: macroGoals, GoalThreshold: 10}
}

func TestMacroKeys(t *testing.T) {
	expected := []string{"protein", "carbs", "fat", "fiber", "sugar"}
	if len(MacroKeys) != len(expected) {
		t.Fatalf("MacroKeys length = %d, want %d", len(MacroKeys), len(expected))
	}
	for i, k := range expected {
		if MacroKeys[i] != k {
			t.Errorf("MacroKeys[%d] = %q, want %q", i, MacroKeys[i], k)
		}
	}
}

func TestMacroLabels(t *testing.T) {
	for _, key := range MacroKeys {
		label, ok := MacroLabels[key]
		if !ok {
			t.Errorf("missing label for %q", key)
			continue
		}
		if label.Short == "" || label.Label == "" {
			t.Errorf("empty label for %q", key)
		}
	}
}

func TestGetEnabledMacros(t *testing.T) {
	tests := []struct {
		name   string
		user   MacroUser
		expect []string
	}{
		{"empty", mu(nil, nil), nil},
		{"none enabled", mu(map[string]any{}, nil), nil},
		{"some enabled", mu(map[string]any{"protein": true, "carbs": false, "fat": true}, nil), []string{"protein", "fat"}},
		{"all enabled", mu(map[string]any{"protein": true, "carbs": true, "fat": true, "fiber": true, "sugar": true}, nil), []string{"protein", "carbs", "fat", "fiber", "sugar"}},
		{"preserves order", mu(map[string]any{"sugar": true, "protein": true, "fat": true}, nil), []string{"protein", "fat", "sugar"}},
		{"ignores non-bool", mu(map[string]any{"protein": "yes", "carbs": 1, "fat": true}, nil), []string{"fat"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetEnabledMacros(tt.user)
			if len(got) != len(tt.expect) {
				t.Errorf("GetEnabledMacros() = %v, want %v", got, tt.expect)
				return
			}
			for i := range got {
				if got[i] != tt.expect[i] {
					t.Errorf("GetEnabledMacros()[%d] = %q, want %q", i, got[i], tt.expect[i])
				}
			}
		})
	}
}

func TestComputeMacroStatusLimit(t *testing.T) {
	g := func(n int) *int { return &n }
	tests := []struct {
		total     int
		goal      *int
		threshold int
		wantClass string
	}{
		{1500, g(2000), 10, "macro-stat--success"},
		{2000, g(2000), 10, "macro-stat--success"},
		{2100, g(2000), 10, "macro-stat--warning"},
		{2200, g(2000), 10, "macro-stat--warning"},
		{2201, g(2000), 10, "macro-stat--danger"},
		{0, g(100), 10, "macro-stat--success"},
		{50, nil, 10, ""},
		{50, g(0), 10, ""},
	}
	for _, tt := range tests {
		s := ComputeMacroStatus(tt.total, tt.goal, "limit", tt.threshold)
		if s.StatusClass != tt.wantClass {
			t.Errorf("ComputeMacroStatus(%d, %v, limit, %d).StatusClass = %q, want %q", tt.total, tt.goal, tt.threshold, s.StatusClass, tt.wantClass)
		}
	}
}

func TestComputeMacroStatusTarget(t *testing.T) {
	g := func(n int) *int { return &n }
	tests := []struct {
		total     int
		goal      *int
		threshold int
		wantClass string
	}{
		{140, g(150), 10, "macro-stat--warning"},
		{80, g(150), 10, "macro-stat--danger"},
		{150, g(150), 10, "macro-stat--success"},
		{180, g(150), 10, "macro-stat--success"},
		{0, g(100), 10, "macro-stat--danger"},
	}
	for _, tt := range tests {
		s := ComputeMacroStatus(tt.total, tt.goal, "target", tt.threshold)
		if s.StatusClass != tt.wantClass {
			t.Errorf("ComputeMacroStatus(%d, %v, target, %d).StatusClass = %q, want %q", tt.total, tt.goal, tt.threshold, s.StatusClass, tt.wantClass)
		}
	}
}

func TestComputeMacroStatusCustomThreshold(t *testing.T) {
	g := func(n int) *int { return &n }
	// Threshold 20: 2201 over 2000 = warning (within 20%)
	s := ComputeMacroStatus(2201, g(2000), "limit", 20)
	if s.StatusClass != "macro-stat--warning" {
		t.Errorf("threshold=20, 2201/2000: got %q, want warning", s.StatusClass)
	}
	// Threshold 20: 2401 over 2000 = danger (over 20%)
	s = ComputeMacroStatus(2401, g(2000), "limit", 20)
	if s.StatusClass != "macro-stat--danger" {
		t.Errorf("threshold=20, 2401/2000: got %q, want danger", s.StatusClass)
	}
	// Threshold 0: any overage = danger
	s = ComputeMacroStatus(2001, g(2000), "limit", 0)
	if s.StatusClass != "macro-stat--danger" {
		t.Errorf("threshold=0, 2001/2000: got %q, want danger", s.StatusClass)
	}
}

func TestComputeDotStatus(t *testing.T) {
	tests := []struct{ input, want string }{
		{"macro-stat--success", "under"},
		{"macro-stat--warning", "over"},
		{"macro-stat--danger", "over_threshold"},
		{"", "over"},
	}
	for _, tt := range tests {
		got := ComputeDotStatus(tt.input)
		if got != tt.want {
			t.Errorf("ComputeDotStatus(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestWorstDotStatus(t *testing.T) {
	tests := []struct{ input []string; want string }{
		{nil, "none"},
		{[]string{"under"}, "under"},
		{[]string{"under", "over", "over_threshold"}, "over_threshold"},
		{[]string{"under", "over"}, "over"},
		{[]string{"none", "zero"}, "zero"},
		{[]string{"zero", "under"}, "under"},
	}
	for _, tt := range tests {
		got := WorstDotStatus(tt.input)
		if got != tt.want {
			t.Errorf("WorstDotStatus(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestComputeCaloriesFromMacros(t *testing.T) {
	tests := []struct {
		p, c, f int
		want    *int
	}{
		{0, 0, 0, nil},
		{30, 50, 20, intPtr(500)},
		{25, 0, 0, intPtr(100)},
		{0, 50, 0, intPtr(200)},
		{0, 0, 10, intPtr(90)},
	}
	for _, tt := range tests {
		got := ComputeCaloriesFromMacros(tt.p, tt.c, tt.f)
		if (got == nil) != (tt.want == nil) {
			t.Errorf("ComputeCaloriesFromMacros(%d,%d,%d) = %v, want %v", tt.p, tt.c, tt.f, got, tt.want)
		} else if got != nil && *got != *tt.want {
			t.Errorf("ComputeCaloriesFromMacros(%d,%d,%d) = %d, want %d", tt.p, tt.c, tt.f, *got, *tt.want)
		}
	}
}

func TestIsAutoCalcCalories(t *testing.T) {
	tests := []struct {
		enabled map[string]any
		want    bool
	}{
		{nil, false},
		{map[string]any{}, false},
		{map[string]any{"auto_calc_calories": false}, false},
		{map[string]any{"auto_calc_calories": true}, true},
		{map[string]any{"protein": true, "carbs": true, "fat": true}, false},
	}
	for _, tt := range tests {
		u := MacroUser{MacrosEnabled: tt.enabled}
		got := IsAutoCalcCalories(u)
		if got != tt.want {
			t.Errorf("IsAutoCalcCalories(%v) = %v, want %v", tt.enabled, got, tt.want)
		}
	}
}

func TestGetCalorieGoal(t *testing.T) {
	tests := []struct {
		name string
		u    MacroUser
		want *int
	}{
		{"from macro_goals", MacroUser{MacroGoals: map[string]any{"calories": float64(2000)}}, intPtr(2000)},
		{"fallback to daily_goal", MacroUser{DailyGoal: intPtr(1800), MacroGoals: map[string]any{}}, intPtr(1800)},
		{"prefers macro_goals", MacroUser{DailyGoal: intPtr(1500), MacroGoals: map[string]any{"calories": float64(2000)}}, intPtr(2000)},
		{"nil when neither set", MacroUser{MacroGoals: map[string]any{}}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetCalorieGoal(tt.u)
			if (got == nil) != (tt.want == nil) {
				t.Errorf("GetCalorieGoal() = %v, want %v", got, tt.want)
			} else if got != nil && *got != *tt.want {
				t.Errorf("GetCalorieGoal() = %d, want %d", *got, *tt.want)
			}
		})
	}
}

func intPtr(n int) *int { return &n }
