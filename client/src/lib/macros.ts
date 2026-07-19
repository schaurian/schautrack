import i18n from '@/i18n';

export const MACRO_KEYS = ['protein', 'carbs', 'fat', 'fiber', 'sugar'] as const;
export type MacroKey = (typeof MACRO_KEYS)[number];

export const MACRO_LABELS: Record<MacroKey, { short: string; label: string }> = {
  protein: { short: 'P', label: i18n.t('macros.protein', { ns: 'common' }) },
  carbs: { short: 'C', label: i18n.t('macros.carbs', { ns: 'common' }) },
  fat: { short: 'F', label: i18n.t('macros.fat', { ns: 'common' }) },
  fiber: { short: 'Fi', label: i18n.t('macros.fiber', { ns: 'common' }) },
  sugar: { short: 'S', label: i18n.t('macros.sugar', { ns: 'common' }) },
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

export function computeMacroStatus(total: number, goal: number | null, mode: string, threshold: number): { statusClass: string; statusText: string } {
  if (goal == null || goal === 0) {
    return { statusClass: '', statusText: i18n.t('macros.noGoalSet', { ns: 'common' }) };
  }
  if (mode === 'target') {
    if (total >= goal) {
      const over = total - goal;
      return over > 0
        ? { statusClass: 'macro-stat--success', statusText: i18n.t('macros.overTarget', { ns: 'common', amount: over }) }
        : { statusClass: 'macro-stat--success', statusText: i18n.t('macros.goalMet', { ns: 'common' }) };
    }
    const under = goal - total;
    return under * 100 > goal * threshold
      ? { statusClass: 'macro-stat--danger', statusText: i18n.t('macros.remaining', { ns: 'common', amount: under }) }
      : { statusClass: 'macro-stat--warning', statusText: i18n.t('macros.remaining', { ns: 'common', amount: under }) };
  }
  // Limit mode
  if (total <= goal) {
    return { statusClass: 'macro-stat--success', statusText: i18n.t('macros.remaining', { ns: 'common', amount: goal - total }) };
  }
  const over = total - goal;
  return over * 100 > goal * threshold
    ? { statusClass: 'macro-stat--danger', statusText: i18n.t('macros.over', { ns: 'common', amount: over }) }
    : { statusClass: 'macro-stat--warning', statusText: i18n.t('macros.over', { ns: 'common', amount: over }) };
}
