package service

import (
	"encoding/json"
	"testing"
	"time"
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
		{"weekday match (Monday)", weekdays, "2025-03-17", true},    // Monday
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

func TestComputeStreak(t *testing.T) {
	daily, _ := json.Marshal(Schedule{Type: "daily"})
	// Mon, Wed, Fri (ISO days 1, 3, 5).
	mwf, _ := json.Marshal(Schedule{Type: "weekdays", Days: []int{1, 3, 5}})

	// Reference weekdays for the March 2025 dates used below:
	//   2025-03-17 Mon, 03-18 Tue, 03-19 Wed, 03-20 Thu, 03-21 Fri,
	//   03-22 Sat, 03-23 Sun, 03-24 Mon.

	tests := []struct {
		name            string
		schedule        json.RawMessage
		completions     []string
		asOf            string
		wantStreak      int
		wantMissedSince string
	}{
		{
			name:            "daily perfect streak, today completed",
			schedule:        daily,
			completions:     []string{"2025-03-17", "2025-03-16", "2025-03-15", "2025-03-14", "2025-03-13"},
			asOf:            "2025-03-17",
			wantStreak:      5,
			wantMissedSince: "", // today completed => no missed_since
		},
		{
			name:            "daily with gap, today not completed",
			schedule:        daily,
			completions:     []string{"2025-03-15", "2025-03-14"},
			asOf:            "2025-03-17",
			wantStreak:      0,            // scheduled today, not completed => break at i=0
			wantMissedSince: "2025-03-16", // 03-16 missed, 03-15 completed stops the walk
		},
		{
			name:            "today scheduled but not yet completed, yesterday done",
			schedule:        daily,
			completions:     []string{"2025-03-16", "2025-03-15", "2025-03-14"},
			asOf:            "2025-03-17",
			wantStreak:      0,  // not yet completed today => streak 0 (pins existing behavior)
			wantMissedSince: "", // yesterday completed => nothing missed yet
		},
		{
			name:            "today completed, streak of one",
			schedule:        daily,
			completions:     []string{"2025-03-17"},
			asOf:            "2025-03-17",
			wantStreak:      1,
			wantMissedSince: "",
		},
		{
			name:            "empty history, walks back 30 scheduled days for missed_since",
			schedule:        daily,
			completions:     nil,
			asOf:            "2025-03-17",
			wantStreak:      0,
			wantMissedSince: "2025-02-15", // asOf minus 30 days
		},
		{
			name:            "missed_since crosses a month boundary",
			schedule:        daily,
			completions:     []string{"2025-02-27"},
			asOf:            "2025-03-02",
			wantStreak:      0,
			wantMissedSince: "2025-02-28", // 03-01 and 02-28 missed, 02-27 completed stops it
		},
		{
			name:            "weekly schedule does not break on off-days",
			schedule:        mwf,
			completions:     []string{"2025-03-21", "2025-03-19", "2025-03-17", "2025-03-14"},
			asOf:            "2025-03-21", // Friday
			wantStreak:      4,            // Fri, Wed, Mon, Fri — Tue/Thu/Sat/Sun skipped
			wantMissedSince: "",
		},
		{
			name:            "weekly missed_since only counts scheduled days",
			schedule:        mwf,
			completions:     []string{"2025-03-17"}, // only Monday done
			asOf:            "2025-03-21",           // Friday, not completed
			wantStreak:      0,
			wantMissedSince: "2025-03-19", // Wed missed; Thu/Tue skipped; Mon completed stops it
		},
		{
			name:            "unparseable asOf yields zero values",
			schedule:        daily,
			completions:     []string{"2025-03-17"},
			asOf:            "not-a-date",
			wantStreak:      0,
			wantMissedSince: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStreak, gotMissed := ComputeStreak(tt.schedule, tt.completions, tt.asOf)
			if gotStreak != tt.wantStreak {
				t.Errorf("streak = %d, want %d", gotStreak, tt.wantStreak)
			}
			if gotMissed != tt.wantMissedSince {
				t.Errorf("missedSince = %q, want %q", gotMissed, tt.wantMissedSince)
			}
		})
	}
}

// TestComputeStreakCapsAt365 pins the 365-day look-back window: a daily todo
// completed every day well beyond a year still reports a streak capped at 365,
// and a single gap exactly at the far edge of the window truncates it there.
func TestComputeStreakCapsAt365(t *testing.T) {
	daily, _ := json.Marshal(Schedule{Type: "daily"})
	asOf, _ := time.Parse("2006-01-02", "2025-03-17")

	// Completed for 400 consecutive days ending at asOf — more than the window.
	var full []string
	for i := 0; i < 400; i++ {
		full = append(full, asOf.AddDate(0, 0, -i).Format("2006-01-02"))
	}
	if streak, missed := ComputeStreak(daily, full, "2025-03-17"); streak != 365 || missed != "" {
		t.Errorf("full window: got streak=%d missed=%q, want streak=365 missed=\"\"", streak, missed)
	}

	// Completed for the whole window except the day at the far edge (asOf-364):
	// the walk should count 0..363 (364 days) then break at i=364.
	var gapAtEdge []string
	for i := 0; i < 400; i++ {
		if i == 364 {
			continue // hole exactly at the last day the loop inspects
		}
		gapAtEdge = append(gapAtEdge, asOf.AddDate(0, 0, -i).Format("2006-01-02"))
	}
	if streak, _ := ComputeStreak(daily, gapAtEdge, "2025-03-17"); streak != 364 {
		t.Errorf("gap at window edge: got streak=%d, want 364", streak)
	}
}
