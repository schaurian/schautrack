// Remaining/over feedback for the Today ring and macro bars, and the numbers
// behind a day dot's explanation. Colours stay with computeMacroStatus (which
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

export interface DotReason {
  metric: string;
  total: number;
  goal: number;
  mode: string;
}

/** How far the metric that decided a dot's colour sits from its goal, in percent. */
export function dotReasonDeviation(r: DotReason): { direction: 'over' | 'under'; pct: number } {
  const diff = Math.abs(r.total - r.goal);
  // A coloured dot always means a real miss; "0% over" would read as no reason.
  const pct = r.goal > 0 ? Math.max(1, Math.round((diff / r.goal) * 100)) : 0;
  return { direction: r.total > r.goal ? 'over' : 'under', pct };
}

/** Mirrors service.GetCalorieGoal: the macro calorie goal wins, else dailyGoal. */
export function hasCalorieGoal(user: { dailyGoal: number | null; macroGoals?: Record<string, number> | null }): boolean {
  const macro = user.macroGoals?.calories;
  if (macro != null && macro > 0) return true;
  return user.dailyGoal != null && user.dailyGoal > 0;
}
