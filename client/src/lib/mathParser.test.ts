import { describe, expect, it } from 'vitest';
import { parseAmount } from './mathParser';

// These cases are the TypeScript twin of internal/service/mathparser_test.go.
// The safe-math parser is duplicated in Go and TS (CSP forbids eval in the
// browser), so both implementations must agree on the same table of inputs.
// Keep this file in sync with the Go tests when either parser changes.

describe('parseAmount', () => {
  it('parses simple numbers', () => {
    const cases: Array<[string, boolean, number]> = [
      ['123', true, 123],
      ['0', true, 0],
      ['999', true, 999],
    ];
    for (const [input, ok, value] of cases) {
      expect(parseAmount(input), input).toEqual({ ok, value });
    }
  });

  it('rounds decimals to the nearest integer', () => {
    const cases: Array<[string, number]> = [
      ['123.7', 124],
      ['123.2', 123],
      ['123.5', 124],
    ];
    for (const [input, value] of cases) {
      expect(parseAmount(input), input).toEqual({ ok: true, value });
    }
  });

  it('evaluates arithmetic', () => {
    const cases: Array<[string, number]> = [
      ['100 + 50', 150],
      ['200 - 30', 170],
      ['10 * 5', 50],
      ['100 / 4', 25],
    ];
    for (const [input, value] of cases) {
      expect(parseAmount(input), input).toEqual({ ok: true, value });
    }
  });

  it('respects parentheses', () => {
    const cases: Array<[string, number]> = [
      ['(10 + 20) * 3', 90],
      ['10 + (20 * 3)', 70],
      ['((10 + 5) * 2) - 5', 25],
    ];
    for (const [input, value] of cases) {
      expect(parseAmount(input), input).toEqual({ ok: true, value });
    }
  });

  it('normalizes alternative operator symbols', () => {
    const cases: Array<[string, number]> = [
      ['10 × 5', 50],
      ['10 x 5', 50],
      ['10 X 5', 50],
      ['100 ÷ 4', 25],
      ['10 – 5', 5],
      ['10 — 5', 5],
      ['10 − 5', 5],
    ];
    for (const [input, value] of cases) {
      expect(parseAmount(input), input).toEqual({ ok: true, value });
    }
  });

  it('strips thousands-separator commas', () => {
    const cases: Array<[string, number]> = [
      ['1,000', 1000],
      ['1,234 + 500', 1734],
    ];
    for (const [input, value] of cases) {
      expect(parseAmount(input), input).toEqual({ ok: true, value });
    }
  });

  it('rejects invalid input', () => {
    for (const input of ['', 'abc', '10 + abc', '10 +']) {
      expect(parseAmount(input), input).toEqual({ ok: false, value: 0 });
    }
  });

  it('rejects null and undefined', () => {
    expect(parseAmount(null)).toEqual({ ok: false, value: 0 });
    expect(parseAmount(undefined)).toEqual({ ok: false, value: 0 });
  });

  it('rejects dangerous / non-arithmetic characters', () => {
    const cases = ['eval(1)', '10; alert(1)', '10 & 20', '10 | 20', '10 ^ 20', '10 << 2'];
    for (const input of cases) {
      expect(parseAmount(input).ok, input).toBe(false);
    }
  });

  it('rejects expressions longer than 120 characters', () => {
    const long = '1 + '.repeat(100) + '1';
    expect(parseAmount(long).ok).toBe(false);
  });

  it('rejects malformed parentheses', () => {
    for (const input of ['(10 + 20', '10 + 20)', '((10 + 20)', '(10 + 20))']) {
      expect(parseAmount(input).ok, input).toBe(false);
    }
  });

  it('rejects division by zero', () => {
    for (const input of ['10 / 0', '100 / (5 - 5)']) {
      expect(parseAmount(input).ok, input).toBe(false);
    }
  });

  it('handles negatives and unary operators', () => {
    const cases: Array<[string, number]> = [
      ['-10', -10],
      ['10 + (-5)', 5],
      ['-(10 + 5)', -15],
    ];
    for (const [input, value] of cases) {
      expect(parseAmount(input), input).toEqual({ ok: true, value });
    }
  });

  it('respects operator precedence in complex expressions', () => {
    const cases: Array<[string, number]> = [
      ['100 + 50 * 2 - 10', 190],
      ['(100 + 50) * 2 - 10', 290],
      ['100 / (2 + 3) * 4', 80],
    ];
    for (const [input, value] of cases) {
      expect(parseAmount(input), input).toEqual({ ok: true, value });
    }
  });

  it('enforces the maxAbs bound', () => {
    const cases: Array<[string, number, boolean, number]> = [
      ['9999', 9999, true, 9999],
      ['-9999', 9999, true, -9999],
      ['10000', 9999, false, 0],
      ['-10000', 9999, false, 0],
      ['5000 + 5000', 9999, false, 0],
    ];
    for (const [input, maxAbs, ok, value] of cases) {
      expect(parseAmount(input, { maxAbs }), input).toEqual({ ok, value });
    }
  });
});
