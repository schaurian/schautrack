import { describe, expect, it } from 'vitest';
import { MAX_ENTRY_CALORIES, MAX_ENTRY_MACRO, expressionPreview, validateEntryField } from './entryValidation';

describe('validateEntryField', () => {
  it('treats blank as valid with no value', () => {
    expect(validateEntryField('macro', '')).toEqual({ ok: true, value: null });
    expect(validateEntryField('calories', '   ')).toEqual({ ok: true, value: null });
    expect(validateEntryField('macro', undefined)).toEqual({ ok: true, value: null });
  });

  it('evaluates expressions for macros, which the server only accepts as integers', () => {
    expect(validateEntryField('macro', '2*15')).toEqual({ ok: true, value: 30 });
    expect(validateEntryField('macro', '12.6')).toEqual({ ok: true, value: 13 });
  });

  it('rejects text that is not a number or expression', () => {
    expect(validateEntryField('macro', 'abc')).toMatchObject({ ok: false, error: 'invalid' });
    expect(validateEntryField('calories', '2**3')).toMatchObject({ ok: false, error: 'invalid' });
  });

  it('applies the server bounds: macros 0..999, calories ±9999', () => {
    expect(validateEntryField('macro', String(MAX_ENTRY_MACRO))).toEqual({ ok: true, value: 999 });
    expect(validateEntryField('macro', '1000')).toMatchObject({ ok: false, error: 'range', min: 0, max: 999 });
    expect(validateEntryField('macro', '5-10')).toMatchObject({ ok: false, error: 'range' });
    expect(validateEntryField('calories', '-200')).toEqual({ ok: true, value: -200 });
    expect(validateEntryField('calories', String(MAX_ENTRY_CALORIES))).toEqual({ ok: true, value: 9999 });
    expect(validateEntryField('calories', '10000')).toMatchObject({ ok: false, error: 'range', min: -9999, max: 9999 });
  });

  it('bounds the value after the quantity multiplier, which is what is sent', () => {
    expect(validateEntryField('macro', '500', 1)).toMatchObject({ ok: true });
    expect(validateEntryField('macro', '500', 2)).toMatchObject({ ok: false, error: 'range' });
    expect(validateEntryField('calories', '5000', 2)).toMatchObject({ ok: false, error: 'range' });
  });
});

describe('expressionPreview', () => {
  it('previews the evaluated value of an expression', () => {
    expect(expressionPreview('2*150')).toBe(300);
    expect(expressionPreview('100 + 50')).toBe(150);
    expect(expressionPreview('10x16')).toBe(160);
  });

  it('shows nothing for a plain number, blank, or an invalid expression', () => {
    expect(expressionPreview('150')).toBeNull();
    expect(expressionPreview('1,000')).toBeNull();
    expect(expressionPreview('-5')).toBeNull();
    expect(expressionPreview('12.5')).toBeNull();
    expect(expressionPreview('')).toBeNull();
    expect(expressionPreview('2*')).toBeNull();
    expect(expressionPreview('abc')).toBeNull();
  });
});
