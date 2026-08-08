package service

import (
	"fmt"
	"math"
	"regexp"
	"strings"
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

func ParseAmount(input string, maxAbs int) ParseAmountResult {
	input = strings.TrimSpace(input)
	if input == "" {
		return ParseAmountResult{Ok: false, Value: 0}
	}

	// Normalize input. Stripping spaces and commas are independent global
	// replacements of distinct characters, so their relative order does not
	// matter; commas go first only so the hex check below can still see the
	// spaces.
	expr := strings.ReplaceAll(input, ",", "")

	// Reject hex-looking literals before "x" becomes "*". Without this,
	// "0x10" normalizes to "0*10" and is *silently accepted as 0* — the
	// callers read Value==0 as "no calorie entry", so a pasted hex value
	// writes an empty entry and reports success. Checked before spaces are
	// stripped so an explicitly spaced "0 x 10" is still the multiplication
	// it looks like.
	if hexLiteralRe.MatchString(expr) {
		return ParseAmountResult{Ok: false, Value: 0}
	}

	expr = strings.ReplaceAll(expr, " ", "")
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

func (p *parser) parseNumber() float64 {
	start := p.pos
	for p.pos < len(p.expr) && (p.expr[p.pos] >= '0' && p.expr[p.pos] <= '9' || p.expr[p.pos] == '.') {
		p.pos++
	}
	if start == p.pos {
		p.err = fmt.Errorf("invalid number")
		return 0
	}
	var val float64
	fmt.Sscanf(p.expr[start:p.pos], "%f", &val)
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
	if ch >= '0' && ch <= '9' {
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
