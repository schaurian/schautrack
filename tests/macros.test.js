const { describe, test, expect } = require('@jest/globals');

// Mock the pool before requiring macros module
jest.mock('../src/db/pool', () => ({ pool: { query: jest.fn() } }));

const {
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
} = require('../src/lib/macros');

const { pool } = require('../src/db/pool');

describe('MACRO_KEYS', () => {
  test('contains the expected macro nutrients', () => {
    expect(MACRO_KEYS).toEqual(['protein', 'carbs', 'fat', 'fiber', 'sugar']);
  });
});

describe('MACRO_LABELS', () => {
  test('has labels for all macro keys', () => {
    for (const key of MACRO_KEYS) {
      expect(MACRO_LABELS[key]).toBeDefined();
      expect(MACRO_LABELS[key].short).toBeDefined();
      expect(MACRO_LABELS[key].label).toBeDefined();
    }
  });
});

describe('getEnabledMacros', () => {
  test('returns empty array for null/undefined user', () => {
    expect(getEnabledMacros(null)).toEqual([]);
    expect(getEnabledMacros(undefined)).toEqual([]);
  });

  test('returns empty array when no macros enabled', () => {
    expect(getEnabledMacros({})).toEqual([]);
    expect(getEnabledMacros({ macros_enabled: {} })).toEqual([]);
  });

  test('returns only enabled macros', () => {
    const user = { macros_enabled: { protein: true, carbs: false, fat: true } };
    expect(getEnabledMacros(user)).toEqual(['protein', 'fat']);
  });

  test('returns all macros when all enabled', () => {
    const user = { macros_enabled: { protein: true, carbs: true, fat: true, fiber: true, sugar: true } };
    expect(getEnabledMacros(user)).toEqual(['protein', 'carbs', 'fat', 'fiber', 'sugar']);
  });

  test('preserves MACRO_KEYS order', () => {
    const user = { macros_enabled: { sugar: true, protein: true, fat: true } };
    expect(getEnabledMacros(user)).toEqual(['protein', 'fat', 'sugar']);
  });

  test('ignores non-boolean truthy values', () => {
    const user = { macros_enabled: { protein: 'yes', carbs: 1, fat: true } };
    expect(getEnabledMacros(user)).toEqual(['fat']);
  });
});

describe('getMacroGoals', () => {
  test('returns empty object for null/undefined user', () => {
    expect(getMacroGoals(null)).toEqual({});
    expect(getMacroGoals(undefined)).toEqual({});
  });

  test('returns empty object when no macros enabled', () => {
    const user = { macros_enabled: {}, macro_goals: { protein: 150 } };
    expect(getMacroGoals(user)).toEqual({});
  });

  test('returns goals only for enabled macros', () => {
    const user = {
      macros_enabled: { protein: true, carbs: true, fat: false },
      macro_goals: { protein: 150, carbs: 200, fat: 70 },
    };
    expect(getMacroGoals(user)).toEqual({ protein: 150, carbs: 200 });
  });

  test('omits enabled macros without goals', () => {
    const user = {
      macros_enabled: { protein: true, carbs: true },
      macro_goals: { protein: 150 },
    };
    expect(getMacroGoals(user)).toEqual({ protein: 150 });
  });

  test('includes zero goals', () => {
    const user = {
      macros_enabled: { protein: true },
      macro_goals: { protein: 0 },
    };
    expect(getMacroGoals(user)).toEqual({ protein: 0 });
  });
});

describe('parseMacroInput', () => {
  test('returns null for empty/undefined/null values', () => {
    expect(parseMacroInput(undefined)).toBeNull();
    expect(parseMacroInput(null)).toBeNull();
    expect(parseMacroInput('')).toBeNull();
  });

  test('parses valid integer strings', () => {
    expect(parseMacroInput('0')).toBe(0);
    expect(parseMacroInput('25')).toBe(25);
    expect(parseMacroInput('150')).toBe(150);
  });

  test('parses numeric values', () => {
    expect(parseMacroInput(42)).toBe(42);
    expect(parseMacroInput(0)).toBe(0);
  });

  test('truncates decimal values', () => {
    expect(parseMacroInput('25.7')).toBe(25);
    expect(parseMacroInput('25.2')).toBe(25);
  });

  test('returns null for negative values', () => {
    expect(parseMacroInput('-1')).toBeNull();
    expect(parseMacroInput('-50')).toBeNull();
  });

  test('returns null for non-numeric strings', () => {
    expect(parseMacroInput('abc')).toBeNull();
    expect(parseMacroInput('twelve')).toBeNull();
  });
});

describe('MACRO_GOAL_MODES', () => {
  test('has defaults for all macros and calories', () => {
    expect(MACRO_GOAL_MODES.calories).toBe('limit');
    expect(MACRO_GOAL_MODES.protein).toBe('target');
    expect(MACRO_GOAL_MODES.carbs).toBe('limit');
    expect(MACRO_GOAL_MODES.fat).toBe('limit');
    expect(MACRO_GOAL_MODES.fiber).toBe('target');
    expect(MACRO_GOAL_MODES.sugar).toBe('limit');
  });
});

describe('getMacroModes', () => {
  test('returns defaults for null/undefined user', () => {
    const modes = getMacroModes(null);
    expect(modes.calories).toBe('limit');
    expect(modes.protein).toBe('target');
    expect(modes.fiber).toBe('target');
    expect(modes.carbs).toBe('limit');
  });

  test('returns stored modes when present', () => {
    const user = { macro_goals: { protein_mode: 'limit', calories_mode: 'target' } };
    const modes = getMacroModes(user);
    expect(modes.protein).toBe('limit');
    expect(modes.calories).toBe('target');
    expect(modes.carbs).toBe('limit'); // default
  });

  test('falls back to defaults for missing mode keys', () => {
    const user = { macro_goals: { protein: 150 } };
    const modes = getMacroModes(user);
    expect(modes.protein).toBe('target');
    expect(modes.calories).toBe('limit');
  });
});

describe('computeMacroStatus', () => {
  describe('no goal', () => {
    test('returns empty class for null goal', () => {
      expect(computeMacroStatus(50, null, 'limit')).toEqual({ statusClass: '', statusText: 'No goal set' });
    });

    test('returns empty class for zero goal', () => {
      expect(computeMacroStatus(50, 0, 'target')).toEqual({ statusClass: '', statusText: 'No goal set' });
    });
  });

  describe('limit mode', () => {
    test('returns success when under goal', () => {
      const result = computeMacroStatus(1500, 2000, 'limit');
      expect(result.statusClass).toBe('macro-stat--success');
      expect(result.statusText).toBe('500 remaining');
    });

    test('returns success at exactly the goal', () => {
      const result = computeMacroStatus(2000, 2000, 'limit');
      expect(result.statusClass).toBe('macro-stat--success');
      expect(result.statusText).toBe('0 remaining');
    });

    test('returns warning when slightly over', () => {
      const result = computeMacroStatus(2100, 2000, 'limit');
      expect(result.statusClass).toBe('macro-stat--warning');
      expect(result.statusText).toBe('100 over');
    });

    test('returns warning at exactly 110%', () => {
      const result = computeMacroStatus(2200, 2000, 'limit');
      expect(result.statusClass).toBe('macro-stat--warning');
      expect(result.statusText).toBe('200 over');
    });

    test('returns danger when over 110%', () => {
      const result = computeMacroStatus(2201, 2000, 'limit');
      expect(result.statusClass).toBe('macro-stat--danger');
      expect(result.statusText).toBe('201 over');
    });

    test('returns success when total is 0', () => {
      const result = computeMacroStatus(0, 100, 'limit');
      expect(result.statusClass).toBe('macro-stat--success');
      expect(result.statusText).toBe('100 remaining');
    });
  });

  describe('target mode', () => {
    test('returns empty class when under target', () => {
      const result = computeMacroStatus(80, 150, 'target');
      expect(result.statusClass).toBe('');
      expect(result.statusText).toBe('70 remaining');
    });

    test('returns success when target met exactly', () => {
      const result = computeMacroStatus(150, 150, 'target');
      expect(result.statusClass).toBe('macro-stat--success');
      expect(result.statusText).toBe('Goal met');
    });

    test('returns success when over target', () => {
      const result = computeMacroStatus(180, 150, 'target');
      expect(result.statusClass).toBe('macro-stat--success');
      expect(result.statusText).toBe('30 over target');
    });

    test('returns empty class when total is 0', () => {
      const result = computeMacroStatus(0, 100, 'target');
      expect(result.statusClass).toBe('');
      expect(result.statusText).toBe('100 remaining');
    });
  });
});

describe('isAutoCalcCalories', () => {
  test('returns false for null/undefined user', () => {
    expect(isAutoCalcCalories(null)).toBe(false);
    expect(isAutoCalcCalories(undefined)).toBe(false);
  });

  test('returns false when not all three macros enabled', () => {
    expect(isAutoCalcCalories({ macros_enabled: { protein: true, carbs: true, fat: false } })).toBe(false);
    expect(isAutoCalcCalories({ macros_enabled: { protein: true, carbs: false, fat: true } })).toBe(false);
    expect(isAutoCalcCalories({ macros_enabled: { protein: false, carbs: true, fat: true } })).toBe(false);
  });

  test('returns true when protein, carbs, and fat are all enabled', () => {
    const user = { macros_enabled: { protein: true, carbs: true, fat: true } };
    expect(isAutoCalcCalories(user)).toBe(true);
  });

  test('returns true with extra macros enabled', () => {
    const user = { macros_enabled: { protein: true, carbs: true, fat: true, fiber: true, sugar: true } };
    expect(isAutoCalcCalories(user)).toBe(true);
  });

  test('returns false when macros_enabled is empty', () => {
    expect(isAutoCalcCalories({ macros_enabled: {} })).toBe(false);
  });
});

describe('computeCaloriesFromMacros', () => {
  test('returns null when all zero', () => {
    expect(computeCaloriesFromMacros(0, 0, 0)).toBeNull();
  });

  test('computes P*4 + C*4 + F*9', () => {
    expect(computeCaloriesFromMacros(30, 50, 20)).toBe(30 * 4 + 50 * 4 + 20 * 9); // 500
  });

  test('handles protein only', () => {
    expect(computeCaloriesFromMacros(25, 0, 0)).toBe(100);
  });

  test('handles carbs only', () => {
    expect(computeCaloriesFromMacros(0, 50, 0)).toBe(200);
  });

  test('handles fat only', () => {
    expect(computeCaloriesFromMacros(0, 0, 10)).toBe(90);
  });

  test('handles string inputs', () => {
    expect(computeCaloriesFromMacros('25', '40', '10')).toBe(25 * 4 + 40 * 4 + 10 * 9); // 350
  });

  test('treats NaN as 0', () => {
    expect(computeCaloriesFromMacros('abc', 50, 20)).toBe(0 * 4 + 50 * 4 + 20 * 9); // 380
  });

  test('returns null for all NaN inputs', () => {
    expect(computeCaloriesFromMacros('abc', 'def', 'ghi')).toBeNull();
  });

  test('handles undefined/null as 0', () => {
    expect(computeCaloriesFromMacros(undefined, 50, null)).toBe(200);
  });
});

describe('getMacroTotalsByDate', () => {
  afterEach(() => {
    jest.resetAllMocks();
  });

  test('returns empty map when no rows', async () => {
    pool.query.mockResolvedValue({ rows: [] });
    const result = await getMacroTotalsByDate(1, '2024-01-01', '2024-01-07');
    expect(result).toBeInstanceOf(Map);
    expect(result.size).toBe(0);
    expect(pool.query).toHaveBeenCalledWith(
      expect.stringContaining('SELECT entry_date'),
      [1, '2024-01-01', '2024-01-07']
    );
  });

  test('aggregates rows by date', async () => {
    pool.query.mockResolvedValue({
      rows: [
        { entry_date: '2024-01-01', protein: '120', carbs: '200', fat: '60', fiber: '25', sugar: '40' },
        { entry_date: '2024-01-02', protein: '0', carbs: '0', fat: '0', fiber: '0', sugar: '0' },
      ],
    });
    const result = await getMacroTotalsByDate(1, '2024-01-01', '2024-01-02');
    expect(result.size).toBe(2);
    expect(result.get('2024-01-01')).toEqual({ protein: 120, carbs: 200, fat: 60, fiber: 25, sugar: 40 });
    expect(result.get('2024-01-02')).toEqual({ protein: 0, carbs: 0, fat: 0, fiber: 0, sugar: 0 });
  });

  test('handles non-numeric values gracefully', async () => {
    pool.query.mockResolvedValue({
      rows: [
        { entry_date: '2024-01-01', protein: null, carbs: '', fat: 'abc', fiber: '10', sugar: '0' },
      ],
    });
    const result = await getMacroTotalsByDate(1, '2024-01-01', '2024-01-01');
    expect(result.get('2024-01-01')).toEqual({ protein: 0, carbs: 0, fat: 0, fiber: 10, sugar: 0 });
  });
});
