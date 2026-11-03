import { parseAmount } from './mathParser';

// The bounds POST /entries enforces on the value it receives — the amount
// after the quantity multiplier, since the form sends `value * qty`.
// Keep in sync with MaxEntryCalories / MaxEntryMacro in
// internal/handler/entries_helpers.go; TestClientEntryLimitsMatchServer reads
// this file and fails when they drift.
export const MAX_ENTRY_CALORIES = 9999;
export const MAX_ENTRY_MACRO = 999;

export type EntryField = 'calories' | 'macro';

export type FieldResult =
  | { ok: true; value: number | null }
  | { ok: false; error: 'invalid' | 'range'; min: number; max: number };

const bounds = (field: EntryField) =>
  field === 'calories'
    ? { min: -MAX_ENTRY_CALORIES, max: MAX_ENTRY_CALORIES }
    : { min: 0, max: MAX_ENTRY_MACRO };

/**
 * Validates one entry-form field the way the server will: calories through
 * ParseAmount with a ±9999 bound, macros as a non-negative integer up to 999
 * (the server Atoi's the macro, so the client evaluates any expression and
 * sends the rounded integer). `qty` is the quantity multiplier; the bound
 * applies to the multiplied value because that is what reaches the server.
 * A blank field is valid and has no value.
 */
export function validateEntryField(field: EntryField, raw: string | undefined, qty = 1): FieldResult {
  const { min, max } = bounds(field);
  if (!raw || raw.trim() === '') return { ok: true, value: null };
  const parsed = parseAmount(raw);
  if (!parsed.ok) return { ok: false, error: 'invalid', min, max };
  const total = parsed.value * qty;
  if (parsed.value < min || parsed.value > max || total < min || total > max) {
    return { ok: false, error: 'range', min, max };
  }
  return { ok: true, value: parsed.value };
}

// A plain decimal, optionally signed, once the separators parseAmount ignores
// (whitespace, thousands commas) are gone. Such input needs no "= n" preview.
const PLAIN_NUMBER_RE = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/;

/**
 * The value to preview next to a field, or null when there is nothing to
 * preview: blank input, a plain number, or an expression that does not parse.
 */
export function expressionPreview(raw: string | undefined): number | null {
  if (!raw) return null;
  const compact = raw.replace(/[\s\u0085]/g, '').replace(/,/g, '');
  if (compact === '' || PLAIN_NUMBER_RE.test(compact)) return null;
  const parsed = parseAmount(raw);
  return parsed.ok ? parsed.value : null;
}
