import { describe, expect, it } from 'vitest';
import { parseAmount } from './mathParser';

// These cases are the TypeScript twin of internal/service/mathparser_test.go.
// The safe-math parser is duplicated in Go and TS (CSP forbids eval in the
// browser), so both implementations must agree on the same table of inputs.
// Keep this file in sync with the Go tests when either parser changes.
//
// "Keep in sync" is now enforced rather than requested for the cases that must
// hold on both sides: they live in testdata/parse_amount_cases.json and are run
// by tests/mathParserParity.test.ts here and by TestParseAmountSharedCases in
// Go. Two hand-maintained tables let #351 and #353 diverge silently; one table
// with two runners cannot. Add cases there unless the expectation is specific
// to this implementation.

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
  // The TypeScript twin of TestParseAmountNormalizationEdges in
  // internal/service/mathparser_test.go. This matters more on this side than
  // on the Go side: EntryForm parses the box locally and POSTs the resulting
  // *number*, so for the SPA this parser is the one that decides what gets
  // stored. Keep the two tables in sync.
  it('pins the consequences of the normalization pass', () => {
    const cases: Array<[string, boolean, number, string]> = [
      // Hex-looking input. "x" -> "*" would make "0x10" read as 0*10 and be
      // silently accepted as 0 — which EntryForm sends as `amount: 0`, an
      // empty entry reported as a success. Rejected instead.
      ['0x10', false, 0, 'hex literal rejected, not silently 0'],
      ['0X10', false, 0, 'uppercase hex literal rejected'],
      ['0xff', false, 0, 'hex letters were never valid expression characters'],
      ['0x', false, 0, 'trailing operator after x->*'],
      ['0x0', false, 0, 'hex literal even when the value would be 0 anyway'],
      ['(0x10)', false, 0, 'hex literal rejected inside parentheses'],
      ['5+0x10', false, 0, 'hex literal rejected as a sub-expression'],
      // ...without losing the multiplication shorthand it is carved out of.
      ['2x3', true, 6, 'the multiplication shorthand the rewrite exists for'],
      ['10x16', true, 160, 'left operand ends in 0, still multiplication'],
      ['100x2', true, 200, 'left operand ends in 00, still multiplication'],
      ['1.0x2', true, 2, '0 after a decimal point is not a hex prefix'],
      ['0 x 10', true, 0, 'spaced form is an explicit multiplication by zero'],
      ['1,0x2', true, 20, 'comma is stripped first, so this is 10*2'],

      // Whitespace stripping: ALL whitespace goes, so a space inside a
      // number closes over silently.
      ['5 5', true, 55, 'digits concatenate: a typo becomes a plausible number'],
      ['1 000', true, 1000, 'space as a thousands separator, intended'],
      ['2 x 3', true, 6, 'spaces around operators, intended'],
      ['5 -', false, 0, 'trailing operator still fails the grammar'],
      [' 5 ', true, 5, 'surrounding spaces'],
      ['\t7\n', true, 7, 'tabs and newlines'],
      // No longer a divergence from Go: stripWhitespace there now drops the
      // same set this does, so a NBSP thousands separator is accepted by the
      // v1 API and the import path too (#351). The full whitespace class is
      // pinned in the shared fixture; these are the cases the issue named.
      ['5\u00a05', true, 55, 'NBSP is stripped, exactly as in the Go parser'],
      ['1\u00a0000', true, 1000, 'NBSP thousands separator, what fr-FR and de-CH produce'],
      ['5\u200b5', false, 0, 'U+200B ZWSP is not whitespace in either language: still rejected'],

      // Comma stripping: a comma is ALWAYS a thousands separator, never a
      // decimal point. In an expression parser it cannot be both.
      ['1,000', true, 1000, 'comma as a thousands separator, intended'],
      ['1,234 + 500', true, 1734, 'thousands separator inside an expression'],
      ['1,5', true, 15, 'European decimal becomes 15, NOT 1.5'],
      ['1,50', true, 150, 'same, two decimal places'],
      ['0,4', true, 4, 'same, leading zero'],

      // Sign forms: parseFactor recurses on unary +/-, so signs stack.
      ['+5', true, 5, 'leading unary plus'],
      ['--5', true, 5, 'double negation'],
      ['-+5', true, -5, 'mixed unary signs'],
      ['5--3', true, 8, 'binary minus then unary minus'],
      ['5+-3', true, 2, 'binary plus then unary minus'],

      // Decimal forms: parseNumber still accepts any run of [0-9.], but it
      // now shape-checks the run before handing it to parseFloat, which
      // truncates to the longest valid prefix rather than returning NaN. A
      // fat-fingered '1.2.3' used to be accepted as 1 (#353).
      //
      // parseFactor also admits a leading '.' now, so '.5' and '5.' are
      // symmetric - matching Go, where ParseWeight already accepted '.5'.
      ['5.', true, 5, 'trailing decimal point is a valid literal'],
      ['.5', true, 1, 'leading decimal point too, symmetric with "5." (rounds to 1)'],
      ['.4', true, 0, 'same, and it rounds to an honest zero'],
      ['5..', false, 0, 'two decimal points is not a number: no longer tolerated as 5'],
      ['..5', false, 0, 'leading dots still rejected, now by parseNumber rather than parseFactor'],
      ['.', false, 0, 'a bare dot is not a number'],
      ['5.0.0', false, 0, 'malformed decimal REJECTED, no longer truncated to 5'],
      ['1.2.3', false, 0, 'same: no longer 1.2 rounded to 1'],
      ['1.2.3+1', false, 0, 'a malformed literal fails the whole expression'],

      // Scientific notation: "e" is not an allowed character and the grammar
      // has no exponent operator.
      ['1e1', false, 0, 'no exponent operator in the grammar'],
      ['1E1', false, 0, 'same, uppercase'],
      ['1e+06', false, 0, 'what a stringified 1000000 looks like'],
      ['1.234567e+06', false, 0, 'what a stringified 1234567 looks like'],

      // Non-ASCII digits: no Unicode digit folding is attempted.
      ['０', false, 0, 'fullwidth zero'],
      ['１２３', false, 0, 'fullwidth digits'],
      ['١٢٣', false, 0, 'Arabic-Indic digits'],
      ['½', false, 0, 'vulgar fraction'],

      ['', false, 0, 'empty input'],

      // The negative-half divergence is gone (#408): parseAmount rounds half
      // away from zero via roundHalfAwayFromZero, matching Go's math.Round.
      // The cases moved to testdata/parse_amount_cases.json, where both
      // implementations run them, which is the only place that can prove they
      // still agree.
    ];
    for (const [input, ok, value, why] of cases) {
      expect(parseAmount(input), `${JSON.stringify(input)} (${why})`).toEqual({ ok, value });
    }
  });

  // The ok/0 class, which the Go handler reads as "no calorie component" via
  // `amountResult.Ok && amountResult.Value != 0`. Each of these is arithmetic
  // the user actually expressed as zero. "0x10" used to be in this class and
  // is now rejected above.
  //
  // Compared with `=== 0` rather than toEqual because a negated zero produces
  // JavaScript's -0 ('-0', '-0.4'), which Object.is — and therefore toEqual —
  // distinguishes from 0 while nothing else does: -0 === 0, String(-0) is "0",
  // and JSON.stringify(-0) is "0", so the server can never receive it. Go's
  // int(math.Round(-0.4)) is a plain 0.
  it('accepts honest zeros', () => {
    for (const input of ['0', '0.0', '-0', '-0.4', '(0)', '0.4', '10-10', '5-5', '0*5', '0/1', '0 x 10']) {
      const r = parseAmount(input);
      expect(r.ok, input).toBe(true);
      expect(r.value === 0, `${input} -> ${r.value}`).toBe(true);
    }
  });
});
