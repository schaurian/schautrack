import { describe, expect, it } from 'vitest';
import {
  MAX_ENTRY_CALORIES,
  MAX_ENTRY_MACRO,
  ambiguousDotNumber,
  entryFieldErrorText,
  expressionPreview,
  parseInlineEdit,
  usesDecimalComma,
  validateEntryField,
} from './entryValidation';
import type { TFunction } from 'i18next';

describe('validateEntryField', () => {
  it('treats blank as valid with no value', () => {
    expect(validateEntryField('macro', '')).toEqual({ ok: true, value: null, total: null });
    expect(validateEntryField('calories', '   ')).toEqual({ ok: true, value: null, total: null });
    expect(validateEntryField('macro', undefined)).toEqual({ ok: true, value: null, total: null });
  });

  it('evaluates expressions for macros, which the server only accepts as integers', () => {
    expect(validateEntryField('macro', '2*15')).toMatchObject({ ok: true, total: 30 });
    expect(validateEntryField('macro', '12.6')).toMatchObject({ ok: true, value: 12.6, total: 13 });
  });

  it('rejects text that is not a number or expression', () => {
    expect(validateEntryField('macro', 'abc')).toMatchObject({ ok: false, error: 'invalid' });
    expect(validateEntryField('calories', '2**3')).toMatchObject({ ok: false, error: 'invalid' });
  });

  it('applies the server bounds: macros 0..999, calories ±9999', () => {
    expect(validateEntryField('macro', String(MAX_ENTRY_MACRO))).toMatchObject({ ok: true, total: 999 });
    expect(validateEntryField('macro', '1000')).toMatchObject({ ok: false, error: 'range', min: 0, max: 999 });
    expect(validateEntryField('macro', '5-10')).toMatchObject({ ok: false, error: 'range' });
    expect(validateEntryField('calories', '-200')).toMatchObject({ ok: true, total: -200 });
    expect(validateEntryField('calories', String(MAX_ENTRY_CALORIES))).toMatchObject({ ok: true, total: 9999 });
    expect(validateEntryField('calories', '10000')).toMatchObject({ ok: false, error: 'range', min: -9999, max: 9999 });
  });

  it('bounds the value after the quantity multiplier, which is what is sent', () => {
    expect(validateEntryField('macro', '500', { qty: 1 })).toMatchObject({ ok: true });
    expect(validateEntryField('macro', '500', { qty: 2 })).toMatchObject({ ok: false, error: 'range' });
    expect(validateEntryField('calories', '5000', { qty: 2 })).toMatchObject({ ok: false, error: 'range' });
  });

  it('multiplies by quantity before rounding', () => {
    expect(validateEntryField('macro', '12.5', { qty: 2 })).toMatchObject({ ok: true, total: 25 });
    expect(validateEntryField('calories', '12.5', { qty: 2 })).toMatchObject({ ok: true, total: 25 });
    expect(validateEntryField('macro', '12.5', { qty: 1 })).toMatchObject({ ok: true, total: 13 });
  });

  it('accepts bounds named by a server rejection', () => {
    expect(validateEntryField('macro', '150', { min: 0, max: 100 })).toMatchObject({ ok: false, error: 'range', max: 100 });
    expect(validateEntryField('macro', '50', { min: 0, max: 100 })).toMatchObject({ ok: true });
  });

  // "12,5" in German is twelve and a half. parseAmount reads every comma as a
  // thousands separator, so before the locale step it was stored as 125.
  it('reads the comma as the decimal point in a decimal-comma language', () => {
    expect(validateEntryField('macro', '12,5', { lang: 'de' })).toMatchObject({ ok: true, value: 12.5, total: 13 });
    expect(validateEntryField('macro', '12,5', { lang: 'de', qty: 2 })).toMatchObject({ ok: true, total: 25 });
    expect(validateEntryField('calories', '2*7,5', { lang: 'fr' })).toMatchObject({ ok: true, total: 15 });
    // Grouping and decimal comma together are not supported: rejected, not guessed.
    expect(validateEntryField('calories', '1.000,5', { lang: 'de' })).toMatchObject({ ok: false, error: 'invalid' });
  });

  it('keeps the comma as a thousands separator in English', () => {
    expect(validateEntryField('calories', '1,000', { lang: 'en' })).toMatchObject({ ok: true, total: 1000 });
  });

  it('keeps a dot as the decimal point when it is not thousands-shaped', () => {
    expect(validateEntryField('macro', '12.5', { lang: 'de' })).toMatchObject({ ok: true, value: 12.5 });
    expect(validateEntryField('macro', '0.500', { lang: 'de' })).toMatchObject({ ok: true, value: 0.5 });
  });

  // "1.200" in German could be 1200 (thousands dot) or 1.2 (a decimal typed
  // from a phone keypad). Reading it either way silently is a 1000x error
  // half the time, so it is refused with both readings.
  it('refuses a thousands-shaped dot number in a decimal-comma language', () => {
    expect(validateEntryField('calories', '1.200', { lang: 'de' })).toMatchObject({ ok: false, error: 'ambiguous', whole: '1200', decimal: '1,200' });
    expect(validateEntryField('calories', '1.000.000', { lang: 'fr' })).toMatchObject({ ok: false, error: 'ambiguous', decimal: '1,000,000' });
    expect(validateEntryField('calories', '2*1.200', { lang: 'de' })).toMatchObject({ ok: false, error: 'ambiguous' });
    expect(validateEntryField('calories', '1.200', { lang: 'en' })).toMatchObject({ ok: true, total: 1 });
  });

  // "10.000" as 10000 kcal is over the limit, so that reading is not offered.
  it('offers only the decimal reading when the whole-number one is out of range', () => {
    const r = validateEntryField('calories', '10.000', { lang: 'de' });
    expect(r).toMatchObject({ ok: false, error: 'ambiguous', decimal: '10,000' });
    expect(r).not.toHaveProperty('whole');
    // The bound applies after the quantity: 600 g fits once, not twice.
    expect(validateEntryField('macro', '1.200', { lang: 'de' })).not.toHaveProperty('whole');
    expect(validateEntryField('calories', '5.000', { lang: 'de', qty: 2 })).not.toHaveProperty('whole');
    expect(validateEntryField('calories', '5.000', { lang: 'de', qty: 1 })).toMatchObject({ whole: '5000' });
  });

  it('rejects an English comma that is not a thousands group instead of dropping it', () => {
    expect(validateEntryField('calories', '12,5', { lang: 'en' })).toMatchObject({ ok: false, error: 'invalid' });
  });
});

describe('ambiguousDotNumber', () => {
  it('flags only dots followed by exactly three digits, after a 1-3 digit non-zero lead', () => {
    expect(ambiguousDotNumber('1.200', 'de')).toEqual({ whole: '1200', decimal: '1,200' });
    expect(ambiguousDotNumber('12.500', 'de')).toEqual({ whole: '12500', decimal: '12,500' });
    for (const raw of ['1.5', '12.25', '0.500', '1.2345', '1234.567', '150']) expect(ambiguousDotNumber(raw, 'de')).toBeNull();
    expect(ambiguousDotNumber('1.200', 'en')).toBeNull();
  });
});

describe('parseInlineEdit', () => {
  it('clears on blank and sends the evaluated integer otherwise', () => {
    expect(parseInlineEdit('calories', '  ', 'de')).toEqual({ ok: true, value: null });
    expect(parseInlineEdit('calories', '12,5', 'de')).toEqual({ ok: true, value: 13 });
    expect(parseInlineEdit('macro', '2*15', 'en')).toEqual({ ok: true, value: 30 });
    expect(parseInlineEdit('macro', '0', 'en')).toEqual({ ok: true, value: 0 });
    expect(parseInlineEdit('macro', 'abc', 'en')).toMatchObject({ ok: false, error: 'invalid' });
    expect(parseInlineEdit('macro', '1000', 'en')).toMatchObject({ ok: false, error: 'range' });
  });
});

describe('entryFieldErrorText', () => {
  const t = ((key: string, opts?: Record<string, unknown>) => `${key} ${JSON.stringify(opts ?? {})}`) as unknown as TFunction;
  it('names the quantity in range and computed-calorie errors', () => {
    const range = { ok: false as const, error: 'range' as const, min: 0, max: 999 };
    expect(entryFieldErrorText(t, range, 1)).toContain('entries.fieldRange ');
    expect(entryFieldErrorText(t, range, 3)).toContain('entries.fieldRangeQty');
    expect(entryFieldErrorText(t, { ...range, computed: true }, 1)).toContain('entries.fieldComputedRange ');
    expect(entryFieldErrorText(t, { ...range, computed: true }, 2)).toContain('entries.fieldComputedRangeQty {"max":999,"qty":2}');
    expect(entryFieldErrorText(t, { ...range, error: 'ambiguous', whole: '1200', decimal: '1,200' })).toContain('"whole":"1200"');
    expect(entryFieldErrorText(t, { ...range, error: 'ambiguous', decimal: '10,000' })).toContain('entries.fieldAmbiguousDecimal {"decimal":"10,000"}');
  });
});

describe('usesDecimalComma', () => {
  it('is true for every shipped locale but English', () => {
    expect(usesDecimalComma('en')).toBe(false);
    for (const lang of ['de', 'es', 'fr', 'it', 'nl', 'pl', 'pt']) expect(usesDecimalComma(lang)).toBe(true);
  });
});

describe('expressionPreview', () => {
  it('shows the value that will be saved for an expression', () => {
    expect(expressionPreview('2*150')).toBe('300');
    expect(expressionPreview('100 + 50')).toBe('150');
    expect(expressionPreview('10x16')).toBe('160');
    expect(expressionPreview('2*7,5', 'de')).toBe('15');
    // Rounded, as stored: 37/3 is 12.33, saved as 12.
    expect(expressionPreview('37/3')).toBe('12');
  });

  it('shows the rounded value when the input was only rounded', () => {
    expect(expressionPreview('12,5', 'de')).toBe('13');
    expect(expressionPreview('12.5', 'en')).toBe('13');
    expect(expressionPreview('1,000', 'en')).toBe('1000');
  });

  it('applies the quantity', () => {
    expect(expressionPreview('150', 'en', 2)).toBe('300');
    expect(expressionPreview('12.5', 'en', 2)).toBe('25');
  });

  it('shows nothing when the saved value is what was typed, or nothing can be saved', () => {
    expect(expressionPreview('150')).toBeNull();
    expect(expressionPreview('-5')).toBeNull();
    expect(expressionPreview('')).toBeNull();
    expect(expressionPreview('2*')).toBeNull();
    expect(expressionPreview('abc')).toBeNull();
    expect(expressionPreview('12,5', 'en')).toBeNull();
    expect(expressionPreview('1.200', 'de')).toBeNull();
  });
});
