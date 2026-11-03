// Remaining/over feedback for the Today ring and macro bars, and when to nudge
// a new account toward setting a goal. Colours stay with computeMacroStatus (which
// applies the goal threshold %); this only says how far from the goal you are.

export type GoalDelta =
  | { kind: 'left'; amount: number } // limit mode, at or under the goal
  | { kind: 'over'; amount: number } // past the goal (either mode)
  | { kind: 'toGo'; amount: number } // target mode, not reached yet
  | { kind: 'met'; amount: 0 }; // target mode, exactly reached

export function goalDelta(total: number, goal: number | null, mode: string): GoalDelta | null {
  if (goal == null || goal <= 0) return null;
  if (total > goal) return { kind: 'over', amount: total - goal };
  if (mode === 'target') {
    return total === goal ? { kind: 'met', amount: 0 } : { kind: 'toGo', amount: goal - total };
  }
  return { kind: 'left', amount: goal - total };
}

/** Mirrors service.GetCalorieGoal: the macro calorie goal wins, else dailyGoal. */
export function hasCalorieGoal(user: { dailyGoal: number | null; macroGoals?: Record<string, number> | null }): boolean {
  const macro = user.macroGoals?.calories;
  if (macro != null && macro > 0) return true;
  return user.dailyGoal != null && user.dailyGoal > 0;
}

/**
 * The "Set a calorie goal" card: only on your own dashboard (a friend's view
 * is read-only and their goal is not yours to set), only while calories are
 * tracked, and only until a goal exists.
 */
export function shouldShowGoalPrompt(d: { canEdit: boolean; caloriesEnabled: boolean; dailyGoal: number | null }): boolean {
  return d.canEdit && d.caloriesEnabled && !(d.dailyGoal != null && d.dailyGoal > 0);
}
