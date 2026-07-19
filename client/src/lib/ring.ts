// Ring math for the Today rings: percent-of-goal and status→color mapping.
// Status colors match statusClasses() semantics used by the old stat tiles
// (green-500 / amber-500 / red-500).

const STATUS_COLORS: Record<string, string> = {
  'macro-stat--success': '#22c55e',
  'macro-stat--warning': '#f59e0b',
  'macro-stat--danger': '#ef4444',
};

const MACRO_COLORS: Record<string, string> = {
  kcal: 'var(--color-macro-kcal)',
  protein: 'var(--color-macro-protein)',
  carbs: 'var(--color-macro-carbs)',
  fat: 'var(--color-macro-fat)',
  fiber: 'var(--color-macro-fiber)',
  sugar: 'var(--color-macro-sugar)',
};

export function ringProgress(value: number, goal: number | null): number {
  if (!goal || goal <= 0) return 100;
  return Math.min(100, Math.max(0, (value / goal) * 100));
}

export function ringColor(statusClass: string, macroKey: string): string {
  return STATUS_COLORS[statusClass] || MACRO_COLORS[macroKey] || 'var(--color-primary)';
}
