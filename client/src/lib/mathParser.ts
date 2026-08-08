// Safe mathematical expression evaluator using recursive descent parser
function safeMathEval(expr: string): number {
  let pos = 0;

  function peek() { return pos < expr.length ? expr[pos] : null; }
  function consume() { return pos < expr.length ? expr[pos++] : null; }

  function parseNumber(): number {
    let num = '';
    while (pos < expr.length && /[0-9.]/.test(expr[pos])) {
      num += consume();
    }
    if (num === '' || num === '.') throw new Error('Invalid number');
    const value = parseFloat(num);
    if (!Number.isFinite(value)) throw new Error('Number out of range');
    return value;
  }

  function parseFactor(): number {
    const ch = peek();
    if (ch === '(') { consume(); const result = parseExpression(); if (consume() !== ')') throw new Error('Missing )'); return result; }
    if (ch === '-') { consume(); return -parseFactor(); }
    if (ch === '+') { consume(); return parseFactor(); }
    if (/[0-9]/.test(ch!)) return parseNumber();
    throw new Error('Unexpected: ' + ch);
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
  if (pos < expr.length) throw new Error('Unexpected at ' + pos);
  return result;
}

// Matches a C-style hex literal ("0x10", "0XfF") anywhere in the input. The
// `(^|[^0-9.])` prefix keeps genuine multiplications whose left operand merely
// ends in a zero — "10x16", "100x2", "1.0x2" — out of the match: there the "0"
// continues a longer number and the "x" is the multiplication symbol the
// normalization is there to support.
const HEX_LITERAL_RE = /(^|[^0-9.])0[xX][0-9a-fA-F]/;

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
    .replace(/\s+/g, '')
    .replace(/,/g, '')
    .replace(/[–—−]/g, '-')
    .replace(/[x×]/gi, '*')
    .replace(/÷/g, '/')
    .trim();

  if (!expr || expr.length > 120 || !/^[0-9+\-*/().]+$/.test(expr)) return { ok: false, value: 0 };

  try {
    const value = safeMathEval(expr);
    if (typeof value !== 'number' || !Number.isFinite(value)) return { ok: false, value: 0 };
    const rounded = Math.round(value);
    if (maxAbs !== null && Math.abs(rounded) > maxAbs) return { ok: false, value: 0 };
    return { ok: true, value: rounded };
  } catch {
    return { ok: false, value: 0 };
  }
}
