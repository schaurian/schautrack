package service

import (
	"testing"
	"time"
)

func TestFormatDateInTz(t *testing.T) {
	date := time.Date(2024, 6, 15, 23, 30, 0, 0, time.UTC)
	tests := []struct{ tz, want string }{
		{"Asia/Tokyo", "2024-06-16"},
		{"UTC", "2024-06-15"},
		{"", "2024-06-15"},
		{"Invalid/Zone", "2024-06-15"},
	}
	for _, tt := range tests {
		got := FormatDateInTz(date, tt.tz)
		if got != tt.want {
			t.Errorf("FormatDateInTz(tz=%q) = %q, want %q", tt.tz, got, tt.want)
		}
	}
}

func TestFormatTimeInTz(t *testing.T) {
	date := time.Date(2024, 6, 15, 14, 30, 0, 0, time.UTC)
	tests := []struct{ tz, want string }{
		{"UTC", "14:30"},
		{"Asia/Tokyo", "23:30"},
		{"Invalid/Zone", "14:30"},
	}
	for _, tt := range tests {
		got := FormatTimeInTz(date, tt.tz)
		if got != tt.want {
			t.Errorf("FormatTimeInTz(tz=%q) = %q, want %q", tt.tz, got, tt.want)
		}
	}
}

func TestParseWeight(t *testing.T) {
	tests := []struct {
		input string
		ok    bool
		value float64
	}{
		{"80.5", true, 80.5},
		{"80,5", true, 80.5},
		{"0", false, 0},
		{"-5", false, 0},
		{"1501", false, 0},
		{"", false, 0},
		{"abc", false, 0},
	}
	for _, tt := range tests {
		got := ParseWeight(tt.input)
		if got.Ok != tt.ok {
			t.Errorf("ParseWeight(%q).Ok = %v, want %v", tt.input, got.Ok, tt.ok)
		}
		if got.Ok && got.Value != tt.value {
			t.Errorf("ParseWeight(%q).Value = %v, want %v", tt.input, got.Value, tt.value)
		}
	}
}

func TestSubtractDaysUTC(t *testing.T) {
	tests := []struct{ date string; days int; want string }{
		{"2025-03-15", 13, "2025-03-02"},
		{"2025-03-01", 1, "2025-02-28"},
		{"2024-03-01", 1, "2024-02-29"},
		{"2025-01-01", 2, "2024-12-30"},
	}
	for _, tt := range tests {
		got := SubtractDaysUTC(tt.date, tt.days)
		if got != tt.want {
			t.Errorf("SubtractDaysUTC(%q, %d) = %q, want %q", tt.date, tt.days, got, tt.want)
		}
	}
}

func TestBuildDayOptionsBetween(t *testing.T) {
	days := BuildDayOptionsBetween("2025-03-10", "2025-03-12", 180)
	if len(days) != 3 {
		t.Fatalf("got %d days, want 3", len(days))
	}
	if days[0] != "2025-03-12" || days[2] != "2025-03-10" {
		t.Errorf("got %v, want [2025-03-12, 2025-03-11, 2025-03-10]", days)
	}
}

func TestContainsString(t *testing.T) {
	s := []string{"a", "b", "c"}
	if !ContainsString(s, "b") {
		t.Error("expected true for 'b'")
	}
	if ContainsString(s, "d") {
		t.Error("expected false for 'd'")
	}
}
