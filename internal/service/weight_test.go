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

