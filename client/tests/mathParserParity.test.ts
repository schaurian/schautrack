import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseAmount } from '../src/lib/mathParser';

/**
 * Cross-language parity for parseAmount (issues #351 and #353).
 *
 * The safe-math parser exists twice — Go for the API, TypeScript because CSP
 * forbids `eval()` in the browser (CLAUDE.md rule 12) — and the SPA parses the
 * input box locally and POSTs the resulting *number*, so the two are not a
 * primary/mirror pair: whichever one runs decides what gets stored. When they
 * disagree, the app accepts an input in the browser and rejects the same input
 * from the v1 API or an import file, and nothing tells anyone.
 *
 * They did disagree, twice, and both were found by reading the code rather
 * than by a failing test:
 *
 *   - #351: Go stripped only U+0020, this file's parser stripped all of
 *     Unicode whitespace, so a NBSP thousands separator ("1\u00a0000") worked
 *     in the SPA and 400'd on the API — and vanished silently from an import.
 *   - #353: both discarded their number-conversion error, in two different
 *     ways (fmt.Sscanf vs parseFloat), so "1.2.3" became 1 in Go and 1.2 here.
 *     Same class of bug, two different wrong answers.
 *
 * `mathParser.test.ts` pins this implementation's behaviour, and the Go suite
 * pins that one's; neither forces the two to agree. This file does, by running
 * the *same* table Go's TestParseAmountSharedCases runs:
 * `testdata/parse_amount_cases.json` at the repository root. Add a case there
 * rather than to either per-language table whenever the expectation is not
 * language-specific.
 *
 * It lives in `tests/` rather than `src/` because it reads the fixture with
 * `node:fs`, and `tsc -b` covers only `src` and has no `@types/node`.
 */

interface SharedCase { input: string; ok: boolean; value: number; why: string }

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = resolve(here, '../../testdata/parse_amount_cases.json');
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8')) as {
  _readme: string[];
  cases: SharedCase[];
};

describe('parseAmount cross-language parity', () => {
  it('loads the shared fixture', () => {
    expect(fixture.cases.length).toBeGreaterThan(50);
  });

  // `ok` and `value` are compared separately with `===` rather than with a
  // single `toEqual({ ok, value })`. `toEqual` uses Object.is, which reports
  // -0 !== 0, and JavaScript produces -0 where Go produces a plain 0 for
  // inputs like "-0.4". Nothing observable distinguishes the two (-0 === 0,
  // String(-0) is "0", JSON.stringify(-0) is "0", so the server can never
  // receive one), so a shared table must not be able to fail on it. Such
  // inputs are also kept out of the fixture — see its _readme.
  it('agrees with the Go parser on every shared case', () => {
    for (const { input, ok, value, why } of fixture.cases) {
      const r = parseAmount(input);
      const label = `${JSON.stringify(input)} (${why})`;
      expect(r.ok, label).toBe(ok);
      expect(r.value === value, `${label}: got ${r.value}, want ${value}`).toBe(true);
    }
  });
});
