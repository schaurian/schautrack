import { describe, expect, it } from 'vitest';
import { computeCaloriesFromMacros, computeMacroStatus, getEnabledMacros } from './macros';

describe('computeCaloriesFromMacros', () => {
  it('returns null when all macros are zero', () => {
    expect(computeCaloriesFromMacros(0, 0, 0)).toBeNull();
  });

  it('applies 4/4/9 kcal per gram', () => {
    // 10*4 + 20*4 + 5*9 = 40 + 80 + 45
    expect(computeCaloriesFromMacros(10, 20, 5)).toBe(165);
    expect(computeCaloriesFromMacros(25, 0, 0)).toBe(100);
  });
});

describe('getEnabledMacros', () => {
  it('keeps macro order and only returns explicitly-enabled keys', () => {
    expect(getEnabledMacros({ protein: true, carbs: false, fat: true })).toEqual([
      'protein',
      'fat',
    ]);
  });

  it('ignores unknown or non-true values', () => {
    // @ts-expect-error - exercising loosely-typed runtime input
    expect(getEnabledMacros({ protein: 1, sugar: 'yes', bogus: true })).toEqual([]);
  });
});

describe('computeMacroStatus', () => {
  it('reports no goal when the goal is null or zero', () => {
    expect(computeMacroStatus(50, null, 'target', 10)).toEqual({
      statusClass: '',
      statusText: 'No goal set',
    });
    expect(computeMacroStatus(50, 0, 'limit', 10)).toEqual({
      statusClass: '',
      statusText: 'No goal set',
    });
  });

  describe('target mode', () => {
    it('marks the goal met exactly on target', () => {
      expect(computeMacroStatus(100, 100, 'target', 10)).toEqual({
        statusClass: 'macro-stat--success',
        statusText: 'Goal met',
      });
    });

    it('reports the overshoot when above target', () => {
      expect(computeMacroStatus(120, 100, 'target', 10)).toEqual({
        statusClass: 'macro-stat--success',
        statusText: '20 over target',
      });
    });

    it('flags danger when the remaining amount exceeds the threshold', () => {
      // under=20, 20*100 > 100*10 => danger
      expect(computeMacroStatus(80, 100, 'target', 10)).toEqual({
        statusClass: 'macro-stat--danger',
        statusText: '20 remaining',
      });
    });

    it('warns when the remaining amount is within the threshold', () => {
      // under=5, 5*100 < 100*10 => warning
      expect(computeMacroStatus(95, 100, 'target', 10)).toEqual({
        statusClass: 'macro-stat--warning',
        statusText: '5 remaining',
      });
    });
  });

  describe('limit mode', () => {
    it('reports remaining headroom when at or below the limit', () => {
      expect(computeMacroStatus(80, 100, 'limit', 10)).toEqual({
        statusClass: 'macro-stat--success',
        statusText: '20 remaining',
      });
      expect(computeMacroStatus(100, 100, 'limit', 10)).toEqual({
        statusClass: 'macro-stat--success',
        statusText: '0 remaining',
      });
    });

    it('flags danger when over the limit beyond the threshold', () => {
      // over=20, 20*100 > 100*10 => danger
      expect(computeMacroStatus(120, 100, 'limit', 10)).toEqual({
        statusClass: 'macro-stat--danger',
        statusText: '20 over',
      });
    });

    it('warns when over the limit but within the threshold', () => {
      // over=5, 5*100 < 100*10 => warning
      expect(computeMacroStatus(105, 100, 'limit', 10)).toEqual({
        statusClass: 'macro-stat--warning',
        statusText: '5 over',
      });
    });
  });
});
