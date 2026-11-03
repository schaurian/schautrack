import type { TFunction } from 'i18next';
import { evaluateAmount, roundHalfAwayFromZero } from './mathParser';

// The bounds POST /entries enforces on the value it receives — the amount
// after the quantity multiplier, since the form sends `value * qty`.
// Keep in sync with MaxEntryCalories / MaxEntryMacro in
// internal/handler/entries_helpers.go; TestClientEntryLimitsMatchServer reads
// this file and fails when they drift.
export const MAX_ENTRY_CALORIES = 9999;
export const MAX_ENTRY_MACRO = 999;

export type EntryField = 'calories' | 'macro';

/**
 * `ambiguous`: in a decimal-comma language, "1.200" could be the thousands
 * separator or a decimal point typed from a phone keypad, so it is refused
 * with both readings (`whole`, `decimal`) rather than guessed.
 */
export type FieldError = {
  ok: false;
  error: 'invalid' | 'range' | 'ambiguous';
  min: number;
  max: number;
  whole?: string;
  decimal?: string;
};

/**
 * `value` is the evaluated per-serving amount, unrounded. `total` is what is
 * sent: value × qty, rounded half away from zero — multiplied first, so
 * 12.5 g at qty 2 is 25 rather than round(12.5) × 2 = 26.
 */
export type FieldResult = { ok: true; value: number | null; total: number | null } | FieldError;

/**
 * Whether `lang` writes decimals with a comma ("12,5"). Asked of Intl rather
 * than listed, so a locale added later gets the right answer without anyone
 * remembering this file.
 */
export function usesDecimalComma(lang: string): boolean {
  try {
    const parts = new Intl.NumberFormat(lang).formatToParts(1.5);
    return parts.find((p) => p.type === 'decimal')?.value === ',';
  } catch {
    return false;
  }
}

/**
 * Rewrites the input into the parser's dot-decimal grammar for the active
 * language. The parser only accepts a comma as a thousands separator ("1,000"),
 * which is right in English; in a decimal-comma language "12,5" means twelve
 * and a half, so there the comma becomes the decimal point.
 *
 * The form sends the evaluated number, never this string, so the server's
 * parser (comma = thousands separator, for API callers) is not involved.
 */
export function normalizeDecimal(raw: string, lang: string): string {
  return usesDecimalComma(lang) ? raw.replace(/,/g, '.') : raw;
}

// A number whose dots all sit before exactly three digits, with a 1-3 digit
// lead that is not 0: "1.200", "12.500", "1.000.000". "0.500" and "1.5" are not
// thousands-shaped, so they are plain decimals.
const THOUSANDS_DOT_RE = /^[1-9][0-9]{0,2}(\.[0-9]{3})+$/;

/**
 * In a decimal-comma language, the first number in `raw` that could equally be
 * a thousands-grouped integer ("1.200" = 1200) or a decimal typed with a dot
 * (1.2). Null when there is none, or in a dot-decimal language, where "1.200"
 * is unambiguous.
 */
export function ambiguousDotNumber(raw: string, lang: string): { whole: string; decimal: string } | null {
  if (!usesDecimalComma(lang)) return null;
  for (const run of raw.replace(/[\s\u0085]/g, '').match(/[0-9.,]+/g) ?? []) {
    if (THOUSANDS_DOT_RE.test(run)) return { whole: run.replace(/\./g, ''), decimal: run.replace(/\./g, ',') };
  }
  return null;
}

const bounds = (field: EntryField) =>
  field === 'calories'
    ? { min: -MAX_ENTRY_CALORIES, max: MAX_ENTRY_CALORIES }
    : { min: 0, max: MAX_ENTRY_MACRO };

export interface ValidateOptions {
  qty?: number;
  lang?: string;
  /** Overrides the default bounds, e.g. with the ones a server rejection names. */
  min?: number;
  max?: number;
}

/**
 * Validates one entry-form field the way the server will: an amount
 * expression (the shared math parser), with the total — value × qty, then
 * rounded, which is what is sent — inside the server's bounds: calories
 * ±9999, macros 0..999 (the server Atoi's the macro, so it must arrive as an
 * integer). A blank field is valid and has no value.
 */
export function validateEntryField(field: EntryField, raw: string | undefined, opts: ValidateOptions = {}): FieldResult {
  const qty = opts.qty ?? 1;
  const def = bounds(field);
  const min = opts.min ?? def.min;
  const max = opts.max ?? def.max;
  if (!raw || raw.trim() === '') return { ok: true, value: null, total: null };
  const lang = opts.lang ?? 'en';
  const ambiguous = ambiguousDotNumber(raw, lang);
  if (ambiguous) return { ok: false, error: 'ambiguous', min, max, ...ambiguous };
  const evaluated = evaluateAmount(normalizeDecimal(raw, lang));
  if (!evaluated.ok) return { ok: false, error: 'invalid', min, max };
  const total = roundHalfAwayFromZero(evaluated.value * qty);
  if (total < min || total > max) return { ok: false, error: 'range', min, max };
  return { ok: true, value: evaluated.value, total };
}

/**
 * The value to show as "= n" beside a field: what will actually be saved —
 * value × qty, rounded — or null when that is exactly what was typed ("150"
 * at qty 1), the input is blank, or it does not parse. So "37/3" shows "= 12",
 * German "12,5" shows "= 13", and "150" at qty 2 shows "= 300".
 */
export function expressionPreview(raw: string | undefined, lang = 'en', qty = 1): string | null {
  if (!raw || raw.trim() === '') return null;
  if (ambiguousDotNumber(raw, lang)) return null;
  const evaluated = evaluateAmount(normalizeDecimal(raw, lang));
  if (!evaluated.ok) return null;
  const saved = String(roundHalfAwayFromZero(evaluated.value * qty));
  return saved === raw.trim() ? null : saved;
}

/**
 * An inline edit of a stored value (an entry's pill, a saved food's pill):
 * blank clears the value (null), anything else must validate and is sent as
 * the evaluated integer — never the raw string, which the server's parser
 * reads with English separators, and never a NaN that JSON turns into null.
 */
export function parseInlineEdit(field: EntryField, raw: string, lang: string): { ok: true; value: number | null } | FieldError {
  if (raw.trim() === '') return { ok: true, value: null };
  const r = validateEntryField(field, raw, { lang });
  return r.ok ? { ok: true, value: r.total } : r;
}

/** The message for a field error; `qty` > 1 names the quantity in range errors. */
export function entryFieldErrorText(t: TFunction, err: FieldError & { computed?: boolean }, qty = 1): string {
  if (err.computed) {
    return qty > 1
      ? t('dashboard:entries.fieldComputedRangeQty', { max: err.max, qty })
      : t('dashboard:entries.fieldComputedRange', { max: err.max });
  }
  if (err.error === 'invalid') return t('dashboard:entries.fieldInvalid');
  if (err.error === 'ambiguous') return t('dashboard:entries.fieldAmbiguous', { whole: err.whole, decimal: err.decimal });
  return qty > 1
    ? t('dashboard:entries.fieldRangeQty', { min: err.min, max: err.max, qty })
    : t('dashboard:entries.fieldRange', { min: err.min, max: err.max });
}
