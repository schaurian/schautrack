import { describe, it, expect } from 'vitest';
import { ringProgress, ringColor } from './ring';

describe('ringProgress', () => {
  it('computes percent toward goal', () => expect(ringProgress(50, 200)).toBe(25));
  it('caps at 100', () => expect(ringProgress(300, 200)).toBe(100));
  it('is 100 (full neutral ring) with no goal', () => expect(ringProgress(50, null)).toBe(100));
  it('is 100 with goal 0 (avoid div-by-zero)', () => expect(ringProgress(50, 0)).toBe(100));
  it('is 0 for zero value with goal', () => expect(ringProgress(0, 200)).toBe(0));
});

describe('ringColor', () => {
  it('maps success status to green', () => expect(ringColor('macro-stat--success', 'protein')).toBe('#22c55e'));
  it('maps warning status to amber', () => expect(ringColor('macro-stat--warning', 'kcal')).toBe('#f59e0b'));
  it('maps danger status to red', () => expect(ringColor('macro-stat--danger', 'fat')).toBe('#ef4444'));
  it('falls back to the macro color without status', () => expect(ringColor('', 'protein')).toBe('var(--color-macro-protein)'));
  it('falls back to primary for unknown macro', () => expect(ringColor('', 'nope')).toBe('var(--color-primary)'));
});
