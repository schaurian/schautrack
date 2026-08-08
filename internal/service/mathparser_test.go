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

// TestParseAmountNormalizationEdges pins the *consequences* of the
// normalization pass in ParseAmount — the rewrites that happen before the
// expression grammar ever sees the input.
//
// Every rewrite there is deliberate ("1,000" -> 1000, "2x3" -> 2*3), but each
// one also changes what a *malformed* input turns into, and those outcomes are
// what this table records. Nothing here is incidental: if a case below starts
// failing, the normalization order changed and the set of strings the app
// accepts changed with it. Decide again, then update the table.
func TestParseAmountNormalizationEdges(t *testing.T) {
	tests := []struct {
		input string
		ok    bool
		value int
		why   string
	}{
		// --- Hex-looking input -------------------------------------------
		// "x" -> "*" makes "0x10" read as 0*10. Accepting that silently
		// yields Value=0, which every caller reads as "no calorie entry", so
		// a pasted hex value writes an empty entry and reports success.
		// ParseAmount rejects hex literals outright instead.
		{"0x10", false, 0, "hex literal rejected, not silently 0"},
		{"0X10", false, 0, "uppercase hex literal rejected"},
		{"0xff", false, 0, "hex letters were never valid expression characters"},
		{"0xFF", false, 0, "same, uppercase"},
		{"0x", false, 0, "trailing operator after x->*"},
		{"0x0", false, 0, "hex literal even when the value would be 0 anyway"},
		{"(0x10)", false, 0, "hex literal rejected inside parentheses"},
		{"5+0x10", false, 0, "hex literal rejected as a sub-expression"},

		// The hex rejection must not cost us the multiplication shorthand it
		// is carved out of: a "0" that merely ends a longer number is not the
		// start of a hex literal.
		{"2x3", true, 6, "the multiplication shorthand the rewrite exists for"},
		{"10x16", true, 160, "left operand ends in 0, still multiplication"},
		{"100x2", true, 200, "left operand ends in 00, still multiplication"},
		{"1.0x2", true, 2, "0 after a decimal point is not a hex prefix"},
		{"0 x 10", true, 0, "spaced form is an explicit multiplication by zero"},
		{"1,0x2", true, 20, "comma is stripped first, so this is 10*2"},

		// --- Space stripping ---------------------------------------------
		// ALL spaces go, so a space inside a number closes over silently.
		{"5 5", true, 55, "digits concatenate: a typo becomes a plausible number"},
		{"1 000", true, 1000, "space as a thousands separator, intended"},
		{"2 x 3", true, 6, "spaces around operators, intended"},
		{"5 -", false, 0, "trailing operator still fails the grammar"},
		{" 5 ", true, 5, "surrounding spaces"},
		{"\t7\n", true, 7, "TrimSpace handles tabs/newlines at the ends"},
		// Only U+0020 is stripped, not Unicode whitespace. NBSP survives
		// into the expression and fails validExprRe.
		{"5\u00a05", false, 0, "non-breaking space is not stripped"},
		{"1\u00a0000", false, 0, "NBSP thousands separator is rejected, unlike a plain space"},

		// --- Comma stripping ----------------------------------------------
		{"1,000", true, 1000, "comma as a thousands separator, intended"},
		{"1,234 + 500", true, 1734, "thousands separator inside an expression"},
		// A comma is ALWAYS a thousands separator here, never a decimal
		// point. In an expression parser it cannot be both: "1,5+2,5" would
		// be unresolvable against "1,234". ParseWeight, which parses a single
		// scalar and has no such ambiguity, decides the opposite way — see
		// TestParseAmountVsParseWeightSyntaxDivergence.
		{"1,5", true, 15, "European decimal becomes 15, NOT 1.5"},
		{"1,50", true, 150, "same, two decimal places"},
		{"0,4", true, 4, "same, leading zero"},

		// --- Sign forms -----------------------------------------------------
		// parseFactor recurses on unary +/-, so signs stack.
		{"+5", true, 5, "leading unary plus"},
		{"--5", true, 5, "double negation"},
		{"-+5", true, -5, "mixed unary signs"},
		{"5--3", true, 8, "binary minus then unary minus"},
		{"5+-3", true, 2, "binary plus then unary minus"},

		// --- Decimal forms ---------------------------------------------------
		// parseNumber accepts any run of [0-9.] and hands it to Sscanf, whose
		// error is ignored — so a malformed decimal truncates at the first
		// valid prefix rather than failing. parseFactor, however, requires a
		// digit to start a number, which is why ".5" is rejected while "5."
		// is not.
		{"5.", true, 5, "trailing decimal point is tolerated"},
		{".5", false, 0, "leading decimal point is NOT (asymmetric with \"5.\")"},
		{"5..", true, 5, "trailing dots tolerated"},
		{"..5", false, 0, "leading dots rejected"},
		{"5.0.0", true, 5, "malformed decimal truncates to its valid prefix"},
		{"1.2.3", true, 1, "same, and 1.2 rounds to 1"},

		// --- Scientific notation ---------------------------------------------
		// "e" is not in validExprRe and the grammar has no exponent operator.
		// This matters because CreateEntry stringifies the JSON amount with
		// fmt.Sprintf("%v", ...), which renders any float64 >= 1e6 in
		// scientific notation. Rejecting is the right outcome there — such a
		// value is far past MaxEntryCalories anyway — but it is a rejection
		// on syntax, not on range.
		{"1e1", false, 0, "no exponent operator in the grammar"},
		{"1E1", false, 0, "same, uppercase"},
		{"1e+06", false, 0, "what fmt.Sprintf(\"%v\", 1000000.0) produces"},
		{"1.234567e+06", false, 0, "what fmt.Sprintf(\"%v\", 1234567.0) produces"},

		// --- Non-ASCII digits --------------------------------------------------
		// The grammar is byte-oriented ASCII; no Unicode digit folding is
		// attempted, so these fail validExprRe rather than being mis-parsed.
		{"０", false, 0, "fullwidth zero"},
		{"１２３", false, 0, "fullwidth digits"},
		{"١٢٣", false, 0, "Arabic-Indic digits"},
		{"½", false, 0, "vulgar fraction"},
		{"⅓", false, 0, "vulgar fraction"},

		// --- Absent value ---------------------------------------------------
		// The handlers reach ParseAmount via fmt.Sprintf("%v", body["amount"]),
		// so a missing key arrives as this literal string.
		{"<nil>", false, 0, "stringified nil from an absent JSON key"},
		{"", false, 0, "empty input"},
	}

	for _, tt := range tests {
		r := ParseAmount(tt.input, 0)
		if r.Ok != tt.ok || r.Value != tt.value {
			t.Errorf("ParseAmount(%q) = {%v, %d}, want {%v, %d} (%s)",
				tt.input, r.Ok, r.Value, tt.ok, tt.value, tt.why)
		}
	}
}

// TestParseAmountAcceptedZeros pins the Ok=true / Value=0 class specifically.
//
// This class is load-bearing: CreateEntry computes
//
//	hasCalorieEntry := amountResult.Ok && amountResult.Value != 0
//
// so a zero is NOT an error, it means "this request has no calorie component".
// Combined with a macro or a weight, the entry is written with amount = 0 and
// no error is shown. That is the intended reading for every input below —
// each one is arithmetic the user actually expressed as zero.
//
// The input that did NOT belong in this class was "0x10", where the zero came
// from a normalization artefact rather than from anything the user wrote; it
// is now rejected in ParseAmount so it never reaches a caller as a zero. See
// TestClassifyAmountZeroIsNotAnError in internal/handler for the caller-side
// half of this decision.
func TestParseAmountAcceptedZeros(t *testing.T) {
	zeros := []string{"0", "0.0", "-0", "(0)", "0.4", "10-10", "5-5", "0*5", "0/1", "0 x 10"}
	for _, input := range zeros {
		r := ParseAmount(input, 0)
		if !r.Ok || r.Value != 0 {
			t.Errorf("ParseAmount(%q) = {%v, %d}, want {true, 0}", input, r.Ok, r.Value)
		}
	}
}

// TestParseAmountVsParseWeightSyntaxDivergence pins the numeric syntax the two
// parsers deliberately disagree on.
//
// To a user, "calories" and "weight" are the same kind of field: a number typed
// into a box. They are not the same kind of parser, and the difference is
// intentional rather than accidental:
//
//   - ParseAmount is a calculator. It accepts a whole expression grammar
//     ("100+50", "2x3", parentheses) because entering calories means adding up
//     a meal. In an expression, a comma must mean "thousands separator" —
//     it cannot also mean "decimal point", because "1,234" and "1,5" would then
//     be unresolvable against each other.
//   - ParseWeight is a single scalar via strconv.ParseFloat. There is no
//     expression, so there is no ambiguity, so a comma can safely be the
//     European decimal point a scale displays. It also inherits ParseFloat's
//     exponent syntax for free.
//
// The divergence is therefore kept, not removed: collapsing it in either
// direction would either take the calculator away from calories or the comma
// decimal away from weights. This test is the record of that decision, so a
// future change to either parser has to break it on purpose.
func TestParseAmountVsParseWeightSyntaxDivergence(t *testing.T) {
	tests := []struct {
		input       string
		amountOk    bool
		amountValue int
		weightOk    bool
		weightValue float64
		why         string
	}{
		{"1,5", true, 15, true, 1.5, "comma: thousands separator vs decimal point"},
		{"1,000", true, 1000, true, 1.0, "the same string means 1000 kcal or 1.0 kg"},
		{"1e1", false, 0, true, 10, "exponent syntax: grammar has none, ParseFloat does"},
		{".5", false, 0, true, 0.5, "leading decimal point: grammar needs a leading digit"},
		{"2x3", true, 6, false, 0, "expression syntax exists only for amounts"},
		{"100+50", true, 150, false, 0, "same"},
		{"5.", true, 5, true, 5, "trailing decimal point: both accept it"},
	}
	for _, tt := range tests {
		a := ParseAmount(tt.input, 0)
		if a.Ok != tt.amountOk || a.Value != tt.amountValue {
			t.Errorf("ParseAmount(%q) = {%v, %d}, want {%v, %d} (%s)",
				tt.input, a.Ok, a.Value, tt.amountOk, tt.amountValue, tt.why)
		}
		w := ParseWeight(tt.input)
		if w.Ok != tt.weightOk || w.Value != tt.weightValue {
			t.Errorf("ParseWeight(%q) = {%v, %v}, want {%v, %v} (%s)",
				tt.input, w.Ok, w.Value, tt.weightOk, tt.weightValue, tt.why)
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
