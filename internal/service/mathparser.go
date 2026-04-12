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

func ParseAmount(input string, maxAbs int) ParseAmountResult {
	input = strings.TrimSpace(input)
	if input == "" {
		return ParseAmountResult{Ok: false, Value: 0}
	}

	// Normalize input
	expr := strings.ReplaceAll(input, " ", "")
	expr = strings.ReplaceAll(expr, ",", "")
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
