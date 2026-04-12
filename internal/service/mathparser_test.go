package service

import (
	"strings"
	"testing"
)

func TestParseAmountSimpleNumbers(t *testing.T) {
	tests := []struct{ input string; ok bool; value int }{
		{"123", true, 123},
		{"0", true, 0},
		{"999", true, 999},
	}
	for _, tt := range tests {
		r := ParseAmount(tt.input, 0)
		if r.Ok != tt.ok || r.Value != tt.value {
			t.Errorf("ParseAmount(%q) = {%v, %d}, want {%v, %d}", tt.input, r.Ok, r.Value, tt.ok, tt.value)
		}
	}
}

func TestParseAmountDecimalRounding(t *testing.T) {
	tests := []struct{ input string; value int }{
		{"123.7", 124},
		{"123.2", 123},
		{"123.5", 124},
	}
	for _, tt := range tests {
		r := ParseAmount(tt.input, 0)
		if !r.Ok || r.Value != tt.value {
			t.Errorf("ParseAmount(%q) = {%v, %d}, want {true, %d}", tt.input, r.Ok, r.Value, tt.value)
		}
	}
}

func TestParseAmountArithmetic(t *testing.T) {
	tests := []struct{ input string; value int }{
		{"100 + 50", 150},
		{"200 - 30", 170},
		{"10 * 5", 50},
		{"100 / 4", 25},
	}
	for _, tt := range tests {
		r := ParseAmount(tt.input, 0)
		if !r.Ok || r.Value != tt.value {
			t.Errorf("ParseAmount(%q) = {%v, %d}, want {true, %d}", tt.input, r.Ok, r.Value, tt.value)
		}
	}
}

func TestParseAmountParentheses(t *testing.T) {
	tests := []struct{ input string; value int }{
		{"(10 + 20) * 3", 90},
		{"10 + (20 * 3)", 70},
		{"((10 + 5) * 2) - 5", 25},
	}
	for _, tt := range tests {
		r := ParseAmount(tt.input, 0)
		if !r.Ok || r.Value != tt.value {
			t.Errorf("ParseAmount(%q) = {%v, %d}, want {true, %d}", tt.input, r.Ok, r.Value, tt.value)
		}
	}
}

func TestParseAmountAlternativeSymbols(t *testing.T) {
	tests := []struct{ input string; value int }{
		{"10 × 5", 50},
		{"10 x 5", 50},
		{"100 ÷ 4", 25},
		{"10 – 5", 5},
		{"10 — 5", 5},
		{"10 − 5", 5},
	}
	for _, tt := range tests {
		r := ParseAmount(tt.input, 0)
		if !r.Ok || r.Value != tt.value {
			t.Errorf("ParseAmount(%q) = {%v, %d}, want {true, %d}", tt.input, r.Ok, r.Value, tt.value)
		}
	}
}

func TestParseAmountCommas(t *testing.T) {
	tests := []struct{ input string; value int }{
		{"1,000", 1000},
		{"1,234 + 500", 1734},
	}
	for _, tt := range tests {
		r := ParseAmount(tt.input, 0)
		if !r.Ok || r.Value != tt.value {
			t.Errorf("ParseAmount(%q) = {%v, %d}, want {true, %d}", tt.input, r.Ok, r.Value, tt.value)
		}
	}
}

func TestParseAmountInvalid(t *testing.T) {
	invalids := []string{"", "abc", "10 + abc", "10 +"}
	for _, input := range invalids {
		r := ParseAmount(input, 0)
		if r.Ok {
			t.Errorf("ParseAmount(%q) = ok, want not ok", input)
		}
	}
}

func TestParseAmountDangerous(t *testing.T) {
	invalids := []string{"eval(1)", "10; alert(1)", "10 & 20", "10 | 20", "10 ^ 20", "10 << 2"}
	for _, input := range invalids {
		r := ParseAmount(input, 0)
		if r.Ok {
			t.Errorf("ParseAmount(%q) should be rejected", input)
		}
	}
}

func TestParseAmountTooLong(t *testing.T) {
	long := strings.Repeat("1 + ", 100) + "1"
	r := ParseAmount(long, 0)
	if r.Ok {
		t.Error("expected too-long expression to be rejected")
	}
}

func TestParseAmountMalformedParentheses(t *testing.T) {
	invalids := []string{"(10 + 20", "10 + 20)", "((10 + 20)", "(10 + 20))"}
	for _, input := range invalids {
		r := ParseAmount(input, 0)
		if r.Ok {
			t.Errorf("ParseAmount(%q) should be rejected", input)
		}
	}
}

func TestParseAmountDivisionByZero(t *testing.T) {
	tests := []string{"10 / 0", "100 / (5 - 5)"}
	for _, input := range tests {
		r := ParseAmount(input, 0)
		if r.Ok {
			t.Errorf("ParseAmount(%q) should fail for division by zero", input)
		}
	}
}

func TestParseAmountNegative(t *testing.T) {
	tests := []struct{ input string; value int }{
		{"-10", -10},
		{"10 + (-5)", 5},
		{"-(10 + 5)", -15},
	}
	for _, tt := range tests {
		r := ParseAmount(tt.input, 0)
		if !r.Ok || r.Value != tt.value {
			t.Errorf("ParseAmount(%q) = {%v, %d}, want {true, %d}", tt.input, r.Ok, r.Value, tt.value)
		}
	}
}

func TestParseAmountComplex(t *testing.T) {
	tests := []struct{ input string; value int }{
		{"100 + 50 * 2 - 10", 190},
		{"(100 + 50) * 2 - 10", 290},
		{"100 / (2 + 3) * 4", 80},
	}
	for _, tt := range tests {
		r := ParseAmount(tt.input, 0)
		if !r.Ok || r.Value != tt.value {
			t.Errorf("ParseAmount(%q) = {%v, %d}, want {true, %d}", tt.input, r.Ok, r.Value, tt.value)
		}
	}
}

func TestParseAmountMaxAbs(t *testing.T) {
	tests := []struct{ input string; maxAbs int; ok bool; value int }{
		{"9999", 9999, true, 9999},
		{"-9999", 9999, true, -9999},
		{"10000", 9999, false, 0},
		{"-10000", 9999, false, 0},
		{"5000 + 5000", 9999, false, 0},
	}
	for _, tt := range tests {
		r := ParseAmount(tt.input, tt.maxAbs)
		if r.Ok != tt.ok || r.Value != tt.value {
			t.Errorf("ParseAmount(%q, maxAbs=%d) = {%v, %d}, want {%v, %d}", tt.input, tt.maxAbs, r.Ok, r.Value, tt.ok, tt.value)
		}
	}
}

func TestSafeMathEvalPrecedence(t *testing.T) {
	tests := []struct{ expr string; want float64 }{
		{"2+3*4", 14},
		{"(2+3)*4", 20},
		{"2*3+4", 10},
		{"2*(3+4)", 14},
	}
	for _, tt := range tests {
		got, err := safeMathEval(tt.expr)
		if err != nil || got != tt.want {
			t.Errorf("safeMathEval(%q) = %v, %v, want %v", tt.expr, got, err, tt.want)
		}
	}
}

func TestSafeMathEvalDivisionByZero(t *testing.T) {
	_, err := safeMathEval("10/0")
	if err == nil {
		t.Error("expected division by zero error")
	}
}
