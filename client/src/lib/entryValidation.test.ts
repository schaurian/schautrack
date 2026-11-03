import { describe, expect, it } from 'vitest';
import {
  MAX_ENTRY_CALORIES,
  MAX_ENTRY_MACRO,
  expressionPreview,
  usesDecimalComma,
  validateEntryField,
} from './entryValidation';

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

  // Documented decision: a dot is a decimal point in every language, so
  // German "1.000" is 1 — the preview ("= 1") is what flags it.
  it('treats a dot as a decimal point in every language', () => {
    expect(validateEntryField('calories', '1.000', { lang: 'de' })).toMatchObject({ ok: true, total: 1 });
    expect(validateEntryField('macro', '12.5', { lang: 'de' })).toMatchObject({ ok: true, value: 12.5 });
  });
});

describe('usesDecimalComma', () => {
  it('is true for every shipped locale but English', () => {
    expect(usesDecimalComma('en')).toBe(false);
    for (const lang of ['de', 'es', 'fr', 'it', 'nl', 'pl', 'pt']) expect(usesDecimalComma(lang)).toBe(true);
  });
});

describe('expressionPreview', () => {
  it('previews the evaluated value of an expression', () => {
    expect(expressionPreview('2*150')).toBe('300');
    expect(expressionPreview('100 + 50')).toBe('150');
    expect(expressionPreview('10x16')).toBe('160');
    expect(expressionPreview('2*7,5', 'de')).toBe('15');
  });

  it('previews input the parser reinterpreted', () => {
    expect(expressionPreview('1,000', 'en')).toBe('1000');
    expect(expressionPreview('12,5', 'en')).toBe('125');
    expect(expressionPreview('1.000', 'de')).toBe('1');
    expect(expressionPreview('12.5', 'de')).toBe('12,5');
  });

  it('shows nothing for a plain number, blank, or an invalid expression', () => {
    expect(expressionPreview('150')).toBeNull();
    expect(expressionPreview('-5')).toBeNull();
    expect(expressionPreview('12.5', 'en')).toBeNull();
    expect(expressionPreview('12,5', 'de')).toBeNull();
    expect(expressionPreview('')).toBeNull();
    expect(expressionPreview('2*')).toBeNull();
    expect(expressionPreview('abc')).toBeNull();
  });
});
