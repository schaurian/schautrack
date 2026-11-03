import { describe, it, expect } from 'vitest';
import { goalDelta, dotReasonDeviation, hasCalorieGoal } from './goalFeedback';

describe('goalDelta', () => {
  it('is null without a goal', () => {
    expect(goalDelta(500, null, 'limit')).toBeNull();
    expect(goalDelta(500, 0, 'limit')).toBeNull();
  });
  it('limit under: amount left', () => expect(goalDelta(1720, 2200, 'limit')).toEqual({ kind: 'left', amount: 480 }));
  it('limit exactly at goal: 0 left', () => expect(goalDelta(2200, 2200, 'limit')).toEqual({ kind: 'left', amount: 0 }));
  it('limit over: amount over', () => expect(goalDelta(134, 110, 'limit')).toEqual({ kind: 'over', amount: 24 }));
  it('target under: amount to go', () => expect(goalDelta(80, 110, 'target')).toEqual({ kind: 'toGo', amount: 30 }));
  it('target met exactly', () => expect(goalDelta(110, 110, 'target')).toEqual({ kind: 'met', amount: 0 }));
  it('target over: amount over', () => expect(goalDelta(134, 110, 'target')).toEqual({ kind: 'over', amount: 24 }));
  it('defaults an unknown mode to limit', () => expect(goalDelta(10, 20, '')).toEqual({ kind: 'left', amount: 10 }));
});

describe('dotReasonDeviation', () => {
  it('rounds the percent over', () => expect(dotReasonDeviation({ metric: 'fat', total: 92, goal: 70, mode: 'limit' })).toEqual({ direction: 'over', pct: 31 }));
  it('reports under for a missed target', () => expect(dotReasonDeviation({ metric: 'protein', total: 60, goal: 120, mode: 'target' })).toEqual({ direction: 'under', pct: 50 }));
  it('never rounds a real overshoot down to 0%', () => expect(dotReasonDeviation({ metric: 'calories', total: 2201, goal: 2200, mode: 'limit' })).toEqual({ direction: 'over', pct: 1 }));
});

describe('hasCalorieGoal', () => {
  it('reads the macro calorie goal first', () => expect(hasCalorieGoal({ dailyGoal: null, macroGoals: { calories: 2000 } })).toBe(true));
  it('falls back to dailyGoal', () => expect(hasCalorieGoal({ dailyGoal: 1800, macroGoals: {} })).toBe(true));
  it('is false with neither', () => expect(hasCalorieGoal({ dailyGoal: null, macroGoals: { calories: 0 } })).toBe(false));
});
