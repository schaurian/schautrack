const { pool } = require('../db/pool');

// Macro nutrient tracking constants
const MACRO_KEYS = ['protein', 'carbs', 'fat', 'fiber', 'sugar'];
const MACRO_LABELS = {
  protein: { short: 'P', label: 'Protein' },
  carbs: { short: 'C', label: 'Carbs' },
  fat: { short: 'F', label: 'Fat' },
  fiber: { short: 'Fi', label: 'Fiber' },
  sugar: { short: 'S', label: 'Sugar' },
};

const getEnabledMacros = (user) => {
  const enabled = user?.macros_enabled || {};
  return MACRO_KEYS.filter(key => enabled[key] === true);
};

const getMacroGoals = (user) => {
  const goals = user?.macro_goals || {};
  const enabled = getEnabledMacros(user);
  const result = {};
  for (const key of enabled) {
    if (goals[key] != null) {
      result[key] = goals[key];
    }
  }
  return result;
};

// Default goal modes: "limit" = stay under, "target" = try to reach
const MACRO_GOAL_MODES = {
  calories: 'limit',
  protein: 'target',
  carbs: 'limit',
  fat: 'limit',
  fiber: 'target',
  sugar: 'limit',
};

const getMacroModes = (user) => {
  const goals = user?.macro_goals || {};
  const result = {};
  for (const key of [...MACRO_KEYS, 'calories']) {
    result[key] = goals[`${key}_mode`] || MACRO_GOAL_MODES[key] || 'limit';
  }
  return result;
};

const computeMacroStatus = (total, goal, mode, threshold) => {
  if (goal == null || goal === 0) {
    return { statusClass: '', statusText: 'No goal set' };
  }

  if (mode === 'target') {
    if (total >= goal) {
      const over = total - goal;
      return { statusClass: 'macro-stat--success', statusText: over > 0 ? `${over} over target` : 'Goal met' };
    }
    const under = goal - total;
    const pctT = threshold != null ? threshold : 10;
    if (under * 100 > goal * pctT) {
      return { statusClass: 'macro-stat--danger', statusText: `${under} remaining` };
    }
    return { statusClass: 'macro-stat--warning', statusText: `${under} remaining` };
  }

  // Limit mode
  if (total <= goal) {
    return { statusClass: 'macro-stat--success', statusText: `${goal - total} remaining` };
  }
  const over = total - goal;
  // Danger when over by more than threshold% of goal
  const pct = threshold != null ? threshold : 10;
  if (over * 100 > goal * pct) {
    return { statusClass: 'macro-stat--danger', statusText: `${over} over` };
  }
  return { statusClass: 'macro-stat--warning', statusText: `${over} over` };
};

// Map macro status CSS class to dot status string
const DOT_STATUS_RANK = { none: 0, zero: 1, under: 2, over: 3, over_threshold: 4 };

const computeDotStatus = (statusClass) => {
  if (statusClass === 'macro-stat--success') return 'under';
  if (statusClass === 'macro-stat--danger') return 'over_threshold';
  if (statusClass === 'macro-stat--warning') return 'over';
  // Empty class = target not met → warning
  return 'over';
};

const worstDotStatus = (statuses) => {
  let worst = 'none';
  for (const s of statuses) {
    if ((DOT_STATUS_RANK[s] || 0) > (DOT_STATUS_RANK[worst] || 0)) {
      worst = s;
    }
  }
  return worst;
};

const parseMacroInput = (value) => {
  if (value === undefined || value === null || value === '') return null;
  const num = parseInt(value, 10);
  return Number.isNaN(num) || num < 0 ? null : num;
};

const getCalorieGoal = (user) => {
  const goals = user?.macro_goals || {};
  if (goals.calories != null) return goals.calories;
  // Fallback for migration period (legacy daily_goal column)
  return user?.daily_goal ?? null;
};

const canEnableAutoCalcCalories = (user) => {
  const enabled = user?.macros_enabled || {};
  return enabled.calories !== false
    && enabled.protein === true
    && enabled.carbs === true
    && enabled.fat === true;
};

const isAutoCalcCalories = (user) => {
  const enabled = user?.macros_enabled || {};
  return enabled.auto_calc_calories === true;
};

const computeCaloriesFromMacros = (protein, carbs, fat) => {
  const p = parseInt(protein, 10) || 0;
  const c = parseInt(carbs, 10) || 0;
  const f = parseInt(fat, 10) || 0;
  if (p === 0 && c === 0 && f === 0) return null;
  return (p * 4) + (c * 4) + (f * 9);
};

async function getMacroTotalsByDate(userId, oldestDate, newestDate) {
  const { rows } = await pool.query(
    `SELECT entry_date,
            COALESCE(SUM(protein_g), 0) AS protein,
            COALESCE(SUM(carbs_g), 0) AS carbs,
            COALESCE(SUM(fat_g), 0) AS fat,
            COALESCE(SUM(fiber_g), 0) AS fiber,
            COALESCE(SUM(sugar_g), 0) AS sugar
       FROM calorie_entries
      WHERE user_id = $1
        AND entry_date BETWEEN $2 AND $3
      GROUP BY entry_date`,
    [userId, oldestDate, newestDate]
  );

  const macrosByDate = new Map();
  rows.forEach((row) => {
    macrosByDate.set(row.entry_date, {
      protein: parseInt(row.protein, 10) || 0,
      carbs: parseInt(row.carbs, 10) || 0,
      fat: parseInt(row.fat, 10) || 0,
      fiber: parseInt(row.fiber, 10) || 0,
      sugar: parseInt(row.sugar, 10) || 0,
    });
  });
  return macrosByDate;
}

module.exports = {
  MACRO_KEYS,
  MACRO_LABELS,
  MACRO_GOAL_MODES,
  DOT_STATUS_RANK,
  getEnabledMacros,
  getMacroGoals,
  getMacroModes,
  getCalorieGoal,
  computeMacroStatus,
  computeDotStatus,
  worstDotStatus,
  parseMacroInput,
  canEnableAutoCalcCalories,
  isAutoCalcCalories,
  computeCaloriesFromMacros,
  getMacroTotalsByDate,
};
