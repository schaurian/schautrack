const { describe, test, expect } = require('@jest/globals');
const { parseAmount, safeMathEval } = require('../src/lib/math-parser');

describe('Math Parser', () => {
  describe('parseAmount', () => {
    test('should parse simple numbers', () => {
      expect(parseAmount('123')).toEqual({ ok: true, value: 123 });
      expect(parseAmount('0')).toEqual({ ok: true, value: 0 });
      expect(parseAmount('999')).toEqual({ ok: true, value: 999 });
    });

    test('should parse decimal numbers and round', () => {
      expect(parseAmount('123.7')).toEqual({ ok: true, value: 124 });
      expect(parseAmount('123.2')).toEqual({ ok: true, value: 123 });
      expect(parseAmount('123.5')).toEqual({ ok: true, value: 124 });
    });

    test('should parse simple arithmetic', () => {
      expect(parseAmount('100 + 50')).toEqual({ ok: true, value: 150 });
      expect(parseAmount('200 - 30')).toEqual({ ok: true, value: 170 });
      expect(parseAmount('10 * 5')).toEqual({ ok: true, value: 50 });
      expect(parseAmount('100 / 4')).toEqual({ ok: true, value: 25 });
    });

    test('should handle parentheses', () => {
      expect(parseAmount('(10 + 20) * 3')).toEqual({ ok: true, value: 90 });
      expect(parseAmount('10 + (20 * 3)')).toEqual({ ok: true, value: 70 });
      expect(parseAmount('((10 + 5) * 2) - 5')).toEqual({ ok: true, value: 25 });
    });

    test('should handle alternative symbols', () => {
      expect(parseAmount('10 × 5')).toEqual({ ok: true, value: 50 });
      expect(parseAmount('10 x 5')).toEqual({ ok: true, value: 50 });
      expect(parseAmount('100 ÷ 4')).toEqual({ ok: true, value: 25 });
      expect(parseAmount('10 – 5')).toEqual({ ok: true, value: 5 });
      expect(parseAmount('10 — 5')).toEqual({ ok: true, value: 5 });
      expect(parseAmount('10 − 5')).toEqual({ ok: true, value: 5 });
    });

    test('should handle commas in numbers', () => {
      expect(parseAmount('1,000')).toEqual({ ok: true, value: 1000 });
      expect(parseAmount('1,234 + 500')).toEqual({ ok: true, value: 1734 });
    });

    test('should handle whitespace', () => {
      expect(parseAmount('  10 + 20  ')).toEqual({ ok: true, value: 30 });
      expect(parseAmount('10+20')).toEqual({ ok: true, value: 30 });
      expect(parseAmount(' ( 10 + 20 ) * 2 ')).toEqual({ ok: true, value: 60 });
    });

    test('should reject invalid expressions', () => {
      expect(parseAmount('')).toEqual({ ok: false, value: 0 });
      expect(parseAmount(null)).toEqual({ ok: false, value: 0 });
      expect(parseAmount(undefined)).toEqual({ ok: false, value: 0 });
      expect(parseAmount('abc')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('10 + abc')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('10 +')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('+ 10')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('10 + + 20')).toEqual({ ok: false, value: 0 });
    });

    test('should reject dangerous expressions', () => {
      expect(parseAmount('eval(1)')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('require("fs")')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('process.exit()')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('10; alert(1)')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('10 & 20')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('10 | 20')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('10 ^ 20')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('10 << 2')).toEqual({ ok: false, value: 0 });
    });

    test('should reject overly long expressions', () => {
      const longExpr = '1 + '.repeat(100) + '1';
      expect(parseAmount(longExpr)).toEqual({ ok: false, value: 0 });
    });

    test('should reject malformed parentheses', () => {
      expect(parseAmount('(10 + 20')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('10 + 20)')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('((10 + 20)')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('(10 + 20))')).toEqual({ ok: false, value: 0 });
    });

    test('should handle division by zero', () => {
      expect(parseAmount('10 / 0')).toEqual({ ok: false, value: 0 });
      expect(parseAmount('100 / (5 - 5)')).toEqual({ ok: false, value: 0 });
    });

    test('should handle negative numbers', () => {
      expect(parseAmount('-10')).toEqual({ ok: true, value: -10 });
      expect(parseAmount('10 + (-5)')).toEqual({ ok: true, value: 5 });
      expect(parseAmount('-(10 + 5)')).toEqual({ ok: true, value: -15 });
    });

    test('should handle complex valid expressions', () => {
      expect(parseAmount('100 + 50 * 2 - 10')).toEqual({ ok: true, value: 190 });
      expect(parseAmount('(100 + 50) * 2 - 10')).toEqual({ ok: true, value: 290 });
      expect(parseAmount('100 / (2 + 3) * 4')).toEqual({ ok: true, value: 80 });
    });
  });

  describe('safeMathEval', () => {
    test('should handle operator precedence correctly', () => {
      expect(safeMathEval('2 + 3 * 4')).toBe(14);
      expect(safeMathEval('(2 + 3) * 4')).toBe(20);
      expect(safeMathEval('2 * 3 + 4')).toBe(10);
      expect(safeMathEval('2 * (3 + 4)')).toBe(14);
    });

    test('should handle division correctly', () => {
      expect(safeMathEval('10 / 2')).toBe(5);
      expect(safeMathEval('100 / 4 / 5')).toBe(5);
      expect(safeMathEval('100 / (4 / 2)')).toBe(50);
    });

    test('should throw on division by zero', () => {
      expect(() => safeMathEval('10 / 0')).toThrow('Division by zero');
      expect(() => safeMathEval('10 / (2 - 2)')).toThrow('Division by zero');
    });

    test('should throw on invalid characters', () => {
      expect(() => safeMathEval('10 + a')).toThrow();
      expect(() => safeMathEval('10 +')).toThrow();
    });

    test('should handle floating point results', () => {
      expect(safeMathEval('10 / 3')).toBeCloseTo(3.333333, 5);
      expect(safeMathEval('1.5 * 2.5')).toBe(3.75);
    });
  });
});