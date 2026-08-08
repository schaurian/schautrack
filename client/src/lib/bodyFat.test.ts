import { describe, it, expect } from 'vitest';
import { MAX_BODY_FAT_PCT, parseBodyFatInput } from './bodyFat';

describe('parseBodyFatInput', () => {
  it('treats an empty field as "clear the reading"', () => {
    // Matches the wire contract: null clears, a number sets. Emptying the
    // input is the only way to remove a reading.
    for (const raw of ['', '   ']) {
      expect(parseBodyFatInput(raw)).toEqual({ ok: true, value: null });
    }
  });

  it('accepts a percentage, including the European comma decimal', () => {
    expect(parseBodyFatInput('24.3')).toEqual({ ok: true, value: 24.3 });
    expect(parseBodyFatInput('24,3')).toEqual({ ok: true, value: 24.3 });
    expect(parseBodyFatInput('  18 ')).toEqual({ ok: true, value: 18 });
    expect(parseBodyFatInput('0.1')).toEqual({ ok: true, value: 0.1 });
  });

  it('accepts exactly the ceiling but nothing above it', () => {
    // service.ParseBodyFat and the weight_entries_body_fat_range CHECK both
    // use `0 < pct <= 75`; drifting from that would either reject values the
    // server takes or let through ones it rejects.
    expect(parseBodyFatInput(String(MAX_BODY_FAT_PCT))).toEqual({ ok: true, value: 75 });
    expect(parseBodyFatInput('75.1')).toEqual({ ok: false });
    expect(parseBodyFatInput('100')).toEqual({ ok: false });
  });

  it('rejects zero and negatives', () => {
    for (const raw of ['0', '-5', '-0.1']) {
      expect(parseBodyFatInput(raw)).toEqual({ ok: false });
    }
  });

  it('rejects anything that is not a number', () => {
    // Number() rather than parseFloat(): parseFloat('24abc') would silently
    // save 24 for a value the user clearly mistyped.
    for (const raw of ['abc', '24abc', 'NaN', 'Infinity', '12.34.56', '1234567890123']) {
      expect(parseBodyFatInput(raw)).toEqual({ ok: false });
    }
  });
});
