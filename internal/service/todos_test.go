package service

import (
	"encoding/json"
	"testing"
)

func TestIsScheduledForDate(t *testing.T) {
	daily, _ := json.Marshal(Schedule{Type: "daily"})
	weekdays, _ := json.Marshal(Schedule{Type: "weekdays", Days: []int{1, 3, 5}}) // Mon, Wed, Fri

	tests := []struct {
		name     string
		schedule json.RawMessage
		date     string
		want     bool
	}{
		{"daily always true", daily, "2025-03-17", true},
		{"daily any date", daily, "2025-01-01", true},
		{"weekday match (Monday)", weekdays, "2025-03-17", true},   // Monday
		{"weekday match (Wednesday)", weekdays, "2025-03-19", true}, // Wednesday
		{"weekday no match (Tuesday)", weekdays, "2025-03-18", false},
		{"weekday no match (Sunday)", weekdays, "2025-03-16", false},
		{"empty schedule", nil, "2025-03-17", false},
		{"empty date", daily, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsScheduledForDate(tt.schedule, tt.date)
			if got != tt.want {
				t.Errorf("IsScheduledForDate(%s, %q) = %v, want %v", tt.schedule, tt.date, got, tt.want)
			}
		})
	}
}

func TestValidateSchedule(t *testing.T) {
	t.Run("daily", func(t *testing.T) {
		r := ValidateSchedule(map[string]any{"type": "daily"})
		if !r.Ok {
			t.Errorf("expected ok for daily schedule")
		}
	})

	t.Run("weekdays valid", func(t *testing.T) {
		r := ValidateSchedule(map[string]any{"type": "weekdays", "days": []any{1.0, 3.0, 5.0}})
		if !r.Ok {
			t.Errorf("expected ok for weekdays schedule: %s", r.Error)
		}
	})

	t.Run("weekdays empty days", func(t *testing.T) {
		r := ValidateSchedule(map[string]any{"type": "weekdays", "days": []any{}})
		if r.Ok {
			t.Error("expected error for empty days")
		}
	})

	t.Run("nil input", func(t *testing.T) {
		r := ValidateSchedule(nil)
		if r.Ok {
			t.Error("expected error for nil")
		}
	})

	t.Run("invalid type", func(t *testing.T) {
		r := ValidateSchedule(map[string]any{"type": "monthly"})
		if r.Ok {
			t.Error("expected error for invalid type")
		}
	})
}

func TestValidateTimeOfDay(t *testing.T) {
	tests := []struct {
		input string
		want  *string
	}{
		{"08:30", strPtr("08:30")},
		{"0:00", strPtr("00:00")},
		{"23:59", strPtr("23:59")},
		{"24:00", nil},
		{"", nil},
		{"abc", nil},
		{"12:60", nil},
	}
	for _, tt := range tests {
		got := ValidateTimeOfDay(tt.input)
		if (got == nil) != (tt.want == nil) {
			t.Errorf("ValidateTimeOfDay(%q) = %v, want %v", tt.input, got, tt.want)
		} else if got != nil && *got != *tt.want {
			t.Errorf("ValidateTimeOfDay(%q) = %q, want %q", tt.input, *got, *tt.want)
		}
	}
}

func strPtr(s string) *string { return &s }
