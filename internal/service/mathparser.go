package service

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type ParseAmountResult struct {
	Ok    bool
	Value int
}

var validExprRe = regexp.MustCompile(`^[0-9+\-*/().]+$`)

// hexLiteralRe matches a C-style hex literal ("0x10", "0XfF") anywhere in the
// input. The `(^|[^0-9.])` prefix keeps genuine multiplications whose left
// operand merely ends in a zero — "10x16", "100x2", "1.0x2" — out of the match:
// there the "0" continues a longer number and the "x" is the multiplication
// symbol the normalization pass is there to support.
//
// Only `0x` followed by a *decimal* digit is actually reachable as a silent
// zero ("0xff" already fails validExprRe because "f" is not an allowed
// character), but the full hex-digit class is matched so the rejection reason
// is the same for every hex-looking input instead of depending on which digits
// happen to be used.
var hexLiteralRe = regexp.MustCompile(`(^|[^0-9.])0[xX][0-9a-fA-F]`)

// stripWhitespace removes every whitespace rune from s, not just U+0020.
//
// This exists because "1 000" with a NBSP (U+00A0) or a narrow NBSP (U+202F)
// is what a fr-FR / de-CH locale actually produces — it is what a user gets
// from pasting a number out of a spreadsheet or a nutrition label — and a
// stray U+FEFF is what a user gets from pasting the first field of a
// BOM-prefixed CSV. Stripping only U+0020 left those characters in the
// expression, where they failed validExprRe and the whole input was rejected.
//
// The set matched here is deliberately the union of Go's unicode.IsSpace and
// JavaScript's `\s`, so it is identical to the `/[\s\u0085]/g` replacement
// used by parseAmount in client/src/lib/mathParser.ts. The two differ in
// exactly two code points, and both are added rather than dropped:
//
//   - U+0085 NEXT LINE: unicode.IsSpace yes, JS `\s` no.
//   - U+FEFF ZERO WIDTH NO-BREAK SPACE (the BOM): unicode.IsSpace no, JS `\s`
//     yes.
//
// U+200B ZERO WIDTH SPACE is in neither and stays rejected on both sides: it
// is not a space separator, and silently deleting invisible characters that
// are not whitespace would widen what the app accepts for no reason.
//
// Keep in sync with client/src/lib/mathParser.ts (issue #351).
func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || r == '\uFEFF' {
			return -1
		}
		return r
	}, s)
}

func ParseAmount(input string, maxAbs int) ParseAmountResult {
	input = strings.TrimSpace(input)
	if input == "" {
		return ParseAmountResult{Ok: false, Value: 0}
	}

	// Normalize input. Stripping whitespace and commas are independent global
	// replacements of distinct characters, so their relative order does not
	// matter; commas go first only so the hex check below can still see the
	// whitespace.
	expr := strings.ReplaceAll(input, ",", "")

	// Reject hex-looking literals before "x" becomes "*". Without this,
	// "0x10" normalizes to "0*10" and is *silently accepted as 0* — the
	// callers read Value==0 as "no calorie entry", so a pasted hex value
	// writes an empty entry and reports success. Checked before whitespace
	// is stripped so an explicitly spaced "0 x 10" is still the
	// multiplication it looks like (that holds for a NBSP-spaced "0 x 10"
	// too, now that stripWhitespace removes those as well).
	if hexLiteralRe.MatchString(expr) {
		return ParseAmountResult{Ok: false, Value: 0}
	}

	expr = stripWhitespace(expr)
	expr = strings.NewReplacer("–", "-", "—", "-", "−", "-").Replace(expr)
	expr = strings.NewReplacer("x", "*", "X", "*", "×", "*").Replace(expr)
	expr = strings.ReplaceAll(expr, "÷", "/")

	if expr == "" || len(expr) > 120 || !validExprRe.MatchString(expr) {
		return ParseAmountResult{Ok: false, Value: 0}
	}

	val, err := safeMathEval(expr)
	if err != nil || math.IsInf(val, 0) || math.IsNaN(val) {
		return ParseAmountResult{Ok: false, Value: 0}
	}

	rounded := int(math.Round(val))
	if maxAbs > 0 && abs(rounded) > maxAbs {
		return ParseAmountResult{Ok: false, Value: 0}
	}
	return ParseAmountResult{Ok: true, Value: rounded}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Recursive descent parser for safe math expressions
func safeMathEval(expr string) (float64, error) {
	p := &parser{expr: expr}
	result := p.parseExpression()
	if p.err != nil {
		return 0, p.err
	}
	if p.pos < len(expr) {
		return 0, fmt.Errorf("unexpected character at position %d", p.pos)
	}
	return result, nil
}

type parser struct {
	expr string
	pos  int
	err  error
}

func (p *parser) peek() byte {
	if p.pos < len(p.expr) {
		return p.expr[p.pos]
	}
	return 0
}

func (p *parser) consume() byte {
	if p.pos < len(p.expr) {
		b := p.expr[p.pos]
		p.pos++
		return b
	}
	return 0
}

// parseNumber consumes a run of [0-9.] and converts it, failing the whole
// parse when that run is not a well-formed decimal.
//
// The run is greedy, so it can swallow more than one decimal point: "5.0.0",
// "1.2.3", "5..". The previous implementation handed the run to fmt.Sscanf
// and *discarded the error*, which made Sscanf's prefix-scanning semantics
// the de facto grammar — "5.0.0" silently became 5 and "1.2.3" silently
// became 1.2 (rounded to 1). A fat-fingered amount was accepted as a
// plausible different amount instead of being reported as invalid (#353).
//
// strconv.ParseFloat has no prefix behaviour: it accepts the run only if the
// *whole* slice is a decimal literal. Since the run contains nothing but
// digits and dots, that is exactly "digits[.digits] | .digits" — no exponent,
// no sign, no hex float, no underscores can reach it.
//
// Keep in sync with parseNumber in client/src/lib/mathParser.ts, where the
// same run is shape-checked against /^(?:\d+(?:\.\d*)?|\.\d+)$/ because
// parseFloat truncates rather than returning NaN.
func (p *parser) parseNumber() float64 {
	start := p.pos
	for p.pos < len(p.expr) && (p.expr[p.pos] >= '0' && p.expr[p.pos] <= '9' || p.expr[p.pos] == '.') {
		p.pos++
	}
	if start == p.pos {
		p.err = fmt.Errorf("invalid number")
		return 0
	}
	lit := p.expr[start:p.pos]
	val, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		p.err = fmt.Errorf("invalid number %q", lit)
		return 0
	}
	return val
}

func (p *parser) parseFactor() float64 {
	if p.err != nil {
		return 0
	}
	ch := p.peek()
	if ch == '(' {
		p.consume()
		result := p.parseExpression()
		if p.consume() != ')' {
			p.err = fmt.Errorf("missing closing parenthesis")
		}
		return result
	}
	if ch == '-' {
		p.consume()
		return -p.parseFactor()
	}
	if ch == '+' {
		p.consume()
		return p.parseFactor()
	}
	// A leading "." starts a number too. Requiring a digit here made ".5"
	// invalid while "5." was fine, and ParseWeight — the other number box in
	// the app — accepts ".5" as 0.5, so the two disagreed on the same
	// keystroke for no reason beyond this check (#353). "." is not an
	// operator in this grammar, so admitting it introduces no ambiguity, and
	// parseNumber rejects the runs that are not real numbers (".", "..5").
	if ch >= '0' && ch <= '9' || ch == '.' {
		return p.parseNumber()
	}
	p.err = fmt.Errorf("unexpected character: %c", ch)
	return 0
}

func (p *parser) parseTerm() float64 {
	left := p.parseFactor()
	for p.err == nil && p.pos < len(p.expr) {
		op := p.peek()
		if op == '*' {
			p.consume()
			left *= p.parseFactor()
		} else if op == '/' {
			p.consume()
			right := p.parseFactor()
			if right == 0 {
				p.err = fmt.Errorf("division by zero")
				return 0
			}
			left /= right
		} else {
			break
		}
	}
	return left
}

func (p *parser) parseExpression() float64 {
	left := p.parseTerm()
	for p.err == nil && p.pos < len(p.expr) {
		op := p.peek()
		if op == '+' {
			p.consume()
			left += p.parseTerm()
		} else if op == '-' {
			p.consume()
			left -= p.parseTerm()
		} else {
			break
		}
	}
	return left
}
