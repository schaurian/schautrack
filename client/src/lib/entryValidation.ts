import { evaluateAmount, roundHalfAwayFromZero } from './mathParser';

// The bounds POST /entries enforces on the value it receives — the amount
// after the quantity multiplier, since the form sends `value * qty`.
// Keep in sync with MaxEntryCalories / MaxEntryMacro in
// internal/handler/entries_helpers.go; TestClientEntryLimitsMatchServer reads
// this file and fails when they drift.
export const MAX_ENTRY_CALORIES = 9999;
export const MAX_ENTRY_MACRO = 999;

export type EntryField = 'calories' | 'macro';

export type FieldError = { ok: false; error: 'invalid' | 'range'; min: number; max: number };

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
 * language. parseAmount treats every comma as a thousands separator, which is
 * right for "1,000" in English and silently wrong for "12,5" in German (it
 * became 125). In a decimal-comma language the comma is the decimal point.
 *
 * A dot is left alone in every language: it is what the phone keypad and most
 * people type for a decimal, so in German "1.000" reads as 1 — never as one
 * thousand. That case is the one the preview exists for: "1.000" shows "= 1".
 *
 * The form sends the evaluated number, never this string, so the server's
 * parser (which keeps the comma-as-thousands rule for the API) is not involved.
 */
export function normalizeDecimal(raw: string, lang: string): string {
  return usesDecimalComma(lang) ? raw.replace(/,/g, '.') : raw;
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
  const evaluated = evaluateAmount(normalizeDecimal(raw, opts.lang ?? 'en'));
  if (!evaluated.ok) return { ok: false, error: 'invalid', min, max };
  const total = roundHalfAwayFromZero(evaluated.value * qty);
  if (total < min || total > max) return { ok: false, error: 'range', min, max };
  return { ok: true, value: evaluated.value, total };
}

/**
 * The value to show as "= n" under a field, or null when there is nothing to
 * add: blank input, an expression that does not parse, or input that already
 * reads as exactly the number it is ("150", or "12,5" in German). Anything
 * the parser reinterpreted — an expression, "1,000" in English, "1.000" in
 * German — is previewed, formatted for the active language.
 */
export function expressionPreview(raw: string | undefined, lang = 'en'): string | null {
  if (!raw || raw.trim() === '') return null;
  const evaluated = evaluateAmount(normalizeDecimal(raw, lang));
  if (!evaluated.ok) return null;
  const formatted = new Intl.NumberFormat(lang, { maximumFractionDigits: 2, useGrouping: false }).format(evaluated.value);
  return formatted === raw.trim() ? null : formatted;
}
