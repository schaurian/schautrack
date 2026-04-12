export const MACRO_KEYS = ['protein', 'carbs', 'fat', 'fiber', 'sugar'] as const;
export type MacroKey = (typeof MACRO_KEYS)[number];

export const MACRO_LABELS: Record<MacroKey, { short: string; label: string }> = {
  protein: { short: 'P', label: 'Protein' },
  carbs: { short: 'C', label: 'Carbs' },
  fat: { short: 'F', label: 'Fat' },
  fiber: { short: 'Fi', label: 'Fiber' },
  sugar: { short: 'S', label: 'Sugar' },
};

export function computeCaloriesFromMacros(protein: number, carbs: number, fat: number): number | null {
  const p = protein || 0;
  const c = carbs || 0;
  const f = fat || 0;
  if (p === 0 && c === 0 && f === 0) return null;
  return p * 4 + c * 4 + f * 9;
}

export function getEnabledMacros(macrosEnabled: Record<string, boolean>): MacroKey[] {
  return MACRO_KEYS.filter((key) => macrosEnabled[key] === true);
}
