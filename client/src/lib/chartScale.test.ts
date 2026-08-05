import { describe, expect, it } from 'vitest';
import { niceStep, niceTicks, clampBand } from './chartScale';

/** Every step must be a 1/2/5 x 10^n value. */
function isRoundStep(step: number): boolean {
  const magnitude = 10 ** Math.floor(Math.log10(step));
  const mantissa = Number((step / magnitude).toFixed(6));
  return mantissa === 1 || mantissa === 2 || mantissa === 5;
}

describe('niceTicks', () => {
  it('produces round ticks for the domain that motivated this helper', () => {
    // Actual weights 105-130 plus a 79.8 target, padded. The old evenTicks()
    // split the raw range into thirds and labelled the axis 54.7 / 79.8 /
    // 104.9 / 130.
    expect(niceTicks(75.8, 134, 6)).toEqual([80, 90, 100, 110, 120, 130]);
  });

  it('keeps every tick inside the domain', () => {
    for (const [lo, hi] of [
      [75.8, 134],
      [54.7, 130],
      [0, 1],
      [-20, 5],
      [1000, 9000],
      [0.3, 0.9],
      [99.4, 100.6],
    ] as const) {
      for (const t of niceTicks(lo, hi, 6)) {
        expect(t).toBeGreaterThanOrEqual(lo);
        expect(t).toBeLessThanOrEqual(hi);
      }
    }
  });

  it('only emits steps from the 1/2/5 x 10^n family', () => {
    for (const [lo, hi] of [
      [0, 1],
      [0, 7],
      [12, 13],
      [54.7, 130],
      [75.8, 134],
      [0.3, 0.9],
      [1000, 9000],
    ] as const) {
      const ticks = niceTicks(lo, hi, 6);
      expect(ticks.length).toBeGreaterThan(1);
      const step = Number((ticks[1] - ticks[0]).toFixed(6));
      expect(isRoundStep(step), `step ${step} for [${lo}, ${hi}]`).toBe(true);
    }
  });

  it('lands near the requested tick count', () => {
    for (const [lo, hi] of [
      [75.8, 134],
      [54.7, 130],
      [0, 1],
      [1000, 9000],
    ] as const) {
      const n = niceTicks(lo, hi, 6).length;
      expect(n, `count for [${lo}, ${hi}]`).toBeGreaterThanOrEqual(4);
      expect(n, `count for [${lo}, ${hi}]`).toBeLessThanOrEqual(9);
    }
  });

  it('spaces ticks evenly', () => {
    const ticks = niceTicks(75.8, 134, 6);
    const gaps = ticks.slice(1).map((t, i) => Number((t - ticks[i]).toFixed(6)));
    expect(new Set(gaps).size).toBe(1);
  });

  it('is free of binary-float drift', () => {
    for (const ticks of [niceTicks(0, 1, 6), niceTicks(0.3, 0.9, 6)]) {
      for (const t of ticks) expect(Number(t.toFixed(6))).toBe(t);
    }
  });

  it('handles a flat domain without emitting a zero-width axis', () => {
    expect(niceTicks(80, 80, 6)).toEqual([80]);
  });

  it('accepts a reversed domain', () => {
    expect(niceTicks(134, 75.8, 6)).toEqual(niceTicks(75.8, 134, 6));
  });

  it('returns nothing for non-finite input rather than NaN ticks', () => {
    expect(niceTicks(NaN, 10, 6)).toEqual([]);
    expect(niceTicks(0, Infinity, 6)).toEqual([]);
  });
});

describe('niceStep', () => {
  it('picks the nearest round step, not always the larger one', () => {
    // span 58.2 over 5 slots = 11.64 -> nearest round step is 10, not 20.
    expect(niceStep(75.8, 134, 6)).toBe(10);
  });

  it('always returns a positive finite step', () => {
    for (const [lo, hi] of [
      [0, 0],
      [5, 5],
      [0, 1e-9],
      [-100, 100],
    ] as const) {
      const s = niceStep(lo, hi, 6);
      expect(Number.isFinite(s)).toBe(true);
      expect(s).toBeGreaterThan(0);
    }
  });
});

describe('clampBand', () => {
  // Screen space: y grows downward, so plot top (10) < plot bottom (200).
  const TOP = 10;
  const BOTTOM = 200;

  it('leaves a band fully inside the plot unchanged', () => {
    expect(clampBand(50, 120, TOP, BOTTOM)).toEqual({ top: 50, bottom: 120 });
  });

  it('trims a band that overruns the bottom edge', () => {
    expect(clampBand(150, 400, TOP, BOTTOM)).toEqual({ top: 150, bottom: BOTTOM });
  });

  it('trims a band that overruns the top edge', () => {
    expect(clampBand(-90, 60, TOP, BOTTOM)).toEqual({ top: TOP, bottom: 60 });
  });

  it('drops a band that falls entirely below the plot', () => {
    // The real case: healthy range 54.7-73.9 against an 80-130 axis.
    expect(clampBand(320, 480, TOP, BOTTOM)).toBeNull();
  });

  it('drops a band that falls entirely above the plot', () => {
    expect(clampBand(-200, -40, TOP, BOTTOM)).toBeNull();
  });

  it('drops a degenerate band grazing an edge', () => {
    expect(clampBand(BOTTOM, 400, TOP, BOTTOM)).toBeNull();
    expect(clampBand(-50, TOP, TOP, BOTTOM)).toBeNull();
  });

  it('accepts inverted top/bottom', () => {
    expect(clampBand(120, 50, TOP, BOTTOM)).toEqual({ top: 50, bottom: 120 });
  });

  it('returns null for non-finite input', () => {
    expect(clampBand(NaN, 50, TOP, BOTTOM)).toBeNull();
  });
});
