package service

import (
	"testing"
)

func TestParseWeightValid(t *testing.T) {
	tests := []struct {
		input string
		value float64
	}{
		{"75.5", 75.5},
		{"100", 100.0},
		{"0.1", 0.1},
		{"1", 1.0},
		{"999.99", 999.99},
		{"1500", 1500.0},
		{"  42.5  ", 42.5},
	}
	for _, tt := range tests {
		r := ParseWeight(tt.input)
		if !r.Ok {
			t.Errorf("ParseWeight(%q) = not ok, want ok with value %v", tt.input, tt.value)
			continue
		}
		if r.Value != tt.value {
			t.Errorf("ParseWeight(%q).Value = %v, want %v", tt.input, r.Value, tt.value)
		}
	}
}

func TestParseWeightInvalid(t *testing.T) {
	tests := []struct {
		input string
		desc  string
	}{
		{"", "empty string"},
		{"abc", "non-numeric"},
		{"-1", "negative"},
		{"0", "zero"},
		{"1501", "exceeds max (1500)"},
		{"   ", "whitespace only"},
		{"12.34.56", "multiple dots"},
		{"NaN", "NaN string"},
		{"Inf", "infinity string"},
	}
	for _, tt := range tests {
		r := ParseWeight(tt.input)
		if r.Ok {
			t.Errorf("ParseWeight(%q) [%s] = ok with value %v, want not ok", tt.input, tt.desc, r.Value)
		}
	}
}

func TestParseWeightCommaDecimal(t *testing.T) {
	// European-style comma decimal separator
	r := ParseWeight("75,5")
	if !r.Ok || r.Value != 75.5 {
		t.Errorf("ParseWeight(\"75,5\") = {ok: %v, value: %v}, want {ok: true, value: 75.5}", r.Ok, r.Value)
	}
}

func TestParseWeightRounding(t *testing.T) {
	// ParseWeight rounds to 2 decimal places
	tests := []struct {
		input string
		value float64
	}{
		{"75.555", 75.56},
		{"75.554", 75.55},
		{"75.5", 75.5},
	}
	for _, tt := range tests {
		r := ParseWeight(tt.input)
		if !r.Ok || r.Value != tt.value {
			t.Errorf("ParseWeight(%q) = {ok: %v, value: %v}, want {ok: true, value: %v}", tt.input, r.Ok, r.Value, tt.value)
		}
	}
}

func TestParseWeightTooLong(t *testing.T) {
	// Input longer than 12 chars after comma normalization
	r := ParseWeight("1234567890123")
	if r.Ok {
		t.Errorf("ParseWeight with >12 char input should be rejected")
	}
}

func TestParseBodyFat(t *testing.T) {
	valid := []struct {
		input string
		value float64
	}{
		{"24.3", 24.3},
		{"18", 18},
		{"  31.5  ", 31.5},
		{"22,7", 22.7},  // European comma decimal, like ParseWeight
		{"24.36", 24.4}, // rounded to the NUMERIC(4,1) column
		{"24.34", 24.3},
		{"75", 75}, // exactly at MaxBodyFatPct
		{"0.1", 0.1},
		{"0.05", 0.1}, // first value that rounds up to 0.1
	}
	for _, tt := range valid {
		got, ok := ParseBodyFat(tt.input)
		assertOkImpliesPositive(t, "ParseBodyFat", tt.input, ok, got)
		if !ok {
			t.Errorf("ParseBodyFat(%q) = not ok, want %v", tt.input, tt.value)
			continue
		}
		if got != tt.value {
			t.Errorf("ParseBodyFat(%q) = %v, want %v", tt.input, got, tt.value)
		}
	}

	invalid := []struct{ input, desc string }{
		{"", "empty"},
		{"   ", "whitespace only"},
		{"abc", "non-numeric"},
		{"0", "zero"},
		{"-5", "negative"},
		{"75.1", "just above the 75% ceiling"},
		// The ceiling is checked before rounding, so a value that would round
		// back down to 75.0 is still out of range as typed. Pinned deliberately:
		// the parser is strict at both ends rather than silently accepting an
		// input the user can see is above the limit.
		{"75.04", "above the ceiling even though it rounds to 75.0"},
		{"100", "a percentage no body can reach"},
		{"NaN", "NaN string"},
		{"Inf", "infinity string"},
		{"1234567890123", "longer than 12 chars"},
		// Rounding boundary: ParseBodyFat rounds to one decimal, so anything
		// below 0.05 rounds to exactly 0 — which
		// CHECK (body_fat > 0 AND body_fat <= 75) rejects. The parser must
		// refuse these itself so the failure is a 400, not a 500.
		{"0.01", "rounds to 0"},
		{"0.04", "rounds to 0"},
		{"0.0499", "rounds to 0"},
		{"1e-07", "rounds to 0"},
	}
	for _, tt := range invalid {
		got, ok := ParseBodyFat(tt.input)
		assertOkImpliesPositive(t, "ParseBodyFat", tt.input, ok, got)
		if ok {
			t.Errorf("ParseBodyFat(%q) [%s] = %v, want not ok", tt.input, tt.desc, got)
		}
	}
}
