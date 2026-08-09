// The decimal literals parseNumber accepts: "5", "5.", "5.0", ".5". This is
// exactly what strconv.ParseFloat accepts on the Go side once the input
// alphabet is narrowed to digits and dots — no exponent, no sign, no hex
// float, no underscores can reach it, because the run that is tested here is
// built from /[0-9.]/ characters only.
const NUMBER_RE = /^(?:\d+(?:\.\d*)?|\.\d+)$/;

/**
 * Rounds a half AWAY FROM ZERO, matching Go's `math.Round`.
 *
 * `Math.round` rounds a half toward +Infinity: `Math.round(-1.5)` is `-1`,
 * while `math.Round(-1.5)` is `-2`. They agree on every positive half and on
 * everything that is not exactly `.5`, and disagree on every negative one — so
 * `10-11.5` previewed as -1 in the browser and was stored as -2 by the server
 * (#408). The preview is the number the user reads before submitting; it has to
 * be the number that gets saved.
 *
 * The client moves rather than the server because the server's value is what is
 * already in the database: changing `math.Round` would silently redefine what a
 * historical entry meant. Away-from-zero is also the symmetric convention —
 * round(1.5) = 2 and round(-1.5) = -2 — which is what an arithmetic preview
 * should do.
 *
 * Keep in sync with ParseAmount in internal/service/mathparser.go.
 */
function roundHalfAwayFromZero(value: number): number {
  return value < 0 ? -Math.round(-value) : Math.round(value);
}

// Safe mathematical expression evaluator using recursive descent parser
function safeMathEval(expr: string): number {
  let pos = 0;

  function peek() { return pos < expr.length ? expr[pos] : null; }
  function consume() { return pos < expr.length ? expr[pos++] : null; }

  // Consumes a run of [0-9.] and converts it, failing the whole parse when
  // that run is not a well-formed decimal.
  //
  // The run is greedy, so it can swallow more than one decimal point:
  // "5.0.0", "1.2.3", "5..". parseFloat does not reject those, it *truncates*
  // to the longest valid prefix — parseFloat("5.0.0") is 5 and
  // parseFloat("1.2.3") is 1.2 — so a fat-fingered amount used to be accepted
  // as a plausible different amount (#353). NUMBER_RE is the shape check that
  // parseFloat does not do; it is the same literal grammar strconv.ParseFloat
  // enforces on the Go side, restricted to the digits-and-dots alphabet this
  // run can contain.
  //
  // Keep in sync with parseNumber in internal/service/mathparser.go.
  function parseNumber(): number {
    let num = '';
    while (pos < expr.length && /[0-9.]/.test(expr[pos])) {
      num += consume() ?? '';
    }
    if (num === '') throw new Error('Invalid number');
    if (!NUMBER_RE.test(num)) throw new Error('Malformed number: ' + num);
    const value = parseFloat(num);
    if (!Number.isFinite(value)) throw new Error('Number out of range');
    return value;
  }

  function parseFactor(): number {
    const ch = peek();
    if (ch === '(') { consume(); const result = parseExpression(); if (consume() !== ')') throw new Error('Missing )'); return result; }
    if (ch === '-') { consume(); return -parseFactor(); }
    if (ch === '+') { consume(); return parseFactor(); }
    // A leading "." starts a number too — see the matching comment in
    // parseFactor in internal/service/mathparser.go. parseNumber rejects the
    // runs that are not real numbers (".", "..5").
    if (ch !== null && /[0-9.]/.test(ch)) return parseNumber();
    throw new Error('Unexpected: ' + String(ch));
  }

  function parseTerm(): number {
    let left = parseFactor();
    while (pos < expr.length) {
      const op = peek();
      if (op === '*') { consume(); left *= parseFactor(); }
      else if (op === '/') { consume(); const right = parseFactor(); if (right === 0) throw new Error('Division by zero'); left /= right; }
      else break;
    }
    return left;
  }

  function parseExpression(): number {
    let left = parseTerm();
    while (pos < expr.length) {
      const op = peek();
      if (op === '+') { consume(); left += parseTerm(); }
      else if (op === '-') { consume(); left -= parseTerm(); }
      else break;
    }
    return left;
  }

  const result = parseExpression();
  if (pos < expr.length) throw new Error(`Unexpected at ${pos}`);
  return result;
}

// Matches a C-style hex literal ("0x10", "0XfF") anywhere in the input. The
// `(^|[^0-9.])` prefix keeps genuine multiplications whose left operand merely
// ends in a zero — "10x16", "100x2", "1.0x2" — out of the match: there the "0"
// continues a longer number and the "x" is the multiplication symbol the
// normalization is there to support.
const HEX_LITERAL_RE = /(^|[^0-9.])0[xX][0-9a-fA-F]/;

// Every whitespace character, defined as the union of JavaScript's `\s` and
// Go's unicode.IsSpace so both parsers strip the identical set. See the call
// site in parseAmount and stripWhitespace in internal/service/mathparser.go.
const WHITESPACE_RE = /[\s\u0085]/g;

export function parseAmount(input: string | number | null | undefined, options: { maxAbs?: number } = {}): { ok: boolean; value: number } {
  const maxAbs = options.maxAbs ?? null;
  if (input === undefined || input === null) return { ok: false, value: 0 };

  // Reject hex-looking literals before "x" becomes "*". Without this, "0x10"
  // normalizes to "0*10" and is silently accepted as 0, which the entry form
  // sends as `amount: 0` — an empty entry reported as a success. Checked
  // before whitespace is stripped so an explicitly spaced "0 x 10" is still
  // the multiplication it looks like.
  // Keep in sync with hexLiteralRe in internal/service/mathparser.go.
  if (HEX_LITERAL_RE.test(String(input).replace(/,/g, ''))) return { ok: false, value: 0 };

  const expr = String(input)
    // Strip every whitespace character, not just U+0020: "1 000" with a NBSP
    // or a narrow NBSP is what fr-FR / de-CH locales produce, and U+FEFF is
    // what a BOM-prefixed CSV paste carries. `\s` covers all of those, and
    // U+0085 NEXT LINE is added because Go's unicode.IsSpace counts it and
    // `\s` does not — the two sides must strip the identical set or the
    // server rejects what this accepts (#351). U+200B ZERO WIDTH SPACE is in
    // neither set and stays rejected on both sides: it is not a space
    // separator.
    // Keep in sync with stripWhitespace in internal/service/mathparser.go.
    .replace(WHITESPACE_RE, '')
    .replace(/,/g, '')
    .replace(/[–—−]/g, '-')
    .replace(/[x×]/gi, '*')
    .replace(/÷/g, '/')
    .trim();

  if (!expr || expr.length > 120 || !/^[0-9+\-*/().]+$/.test(expr)) return { ok: false, value: 0 };

  try {
    const value = safeMathEval(expr);
    if (typeof value !== 'number' || !Number.isFinite(value)) return { ok: false, value: 0 };
    const rounded = roundHalfAwayFromZero(value);
    // Reject anything outside the int32 range even when no maxAbs is given.
    // The Go side must do this because converting an out-of-range float64 to
    // int is implementation-defined there and yields math.MinInt64 (#364);
    // JavaScript has no such trap, but the two parsers have to agree, and the
    // value ends up in an INTEGER column either way. Without this, an
    // unbounded parseAmount("99999999999999999999*99999999999999999999")
    // returned ok on one side and not the other.
    // Keep in sync with the bound in internal/service/mathparser.go.
    if (rounded > 2147483647 || rounded < -2147483648) return { ok: false, value: 0 };
    if (maxAbs !== null && Math.abs(rounded) > maxAbs) return { ok: false, value: 0 };
    return { ok: true, value: rounded };
  } catch {
    return { ok: false, value: 0 };
  }
}
