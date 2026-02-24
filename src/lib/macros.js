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

const computeMacroStatus = (total, goal, mode) => {
  if (goal == null || goal === 0) {
    return { statusClass: '', statusText: 'No goal set' };
  }

  if (mode === 'target') {
    if (total >= goal) {
      const over = total - goal;
      return { statusClass: 'macro-stat--success', statusText: over > 0 ? `${over} over target` : 'Goal met' };
    }
    return { statusClass: '', statusText: `${goal - total} remaining` };
  }

  // Limit mode
  if (total <= goal) {
    return { statusClass: 'macro-stat--success', statusText: `${goal - total} remaining` };
  }
  const over = total - goal;
  // Danger when over by more than 10% of goal
  if (over * 10 > goal) {
    return { statusClass: 'macro-stat--danger', statusText: `${over} over` };
  }
  return { statusClass: 'macro-stat--warning', statusText: `${over} over` };
};

const parseMacroInput = (value) => {
  if (value === undefined || value === null || value === '') return null;
  const num = parseInt(value, 10);
  return Number.isNaN(num) || num < 0 ? null : num;
};

const isAutoCalcCalories = (user) => {
  const enabled = user?.macros_enabled || {};
  return enabled.protein === true
    && enabled.carbs === true
    && enabled.fat === true;
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
  getEnabledMacros,
  getMacroGoals,
  getMacroModes,
  computeMacroStatus,
  parseMacroInput,
  isAutoCalcCalories,
  computeCaloriesFromMacros,
  getMacroTotalsByDate,
};
