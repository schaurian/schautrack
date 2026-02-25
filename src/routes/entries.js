const express = require('express');
const multer = require('multer');
const { pool } = require('../db/pool');
const { requireLogin } = require('../middleware/auth');
const { requireLinkAuth } = require('../middleware/links');
const { csrfProtection } = require('../middleware/csrf');
const { parseAmount } = require('../lib/math-parser');
const { getAcceptedLinkUsers } = require('../lib/links');
const { broadcastEntryChange } = require('./sse');
const {
  parseWeight,
  toInt,
  getUserTimezone,
  formatDateInTz,
  formatTimeInTz
} = require('../lib/utils');
const {
  upsertWeightEntry,
  getWeightEntry,
  getLastWeightEntry,
} = require('../lib/weight');
const {
  MACRO_KEYS,
  MACRO_LABELS,
  getEnabledMacros,
  getMacroGoals,
  getMacroModes,
  getCalorieGoal,
  computeMacroStatus,
  computeDotStatus,
  worstDotStatus,
  parseMacroInput,
  isAutoCalcCalories,
  computeCaloriesFromMacros,
  getMacroTotalsByDate,
} = require('../lib/macros');

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
});

// Constants
const MAX_HISTORY_DAYS = 180;
const DEFAULT_RANGE_DAYS = 14;
const MAX_ENTRY_CALORIES = 9999;
const MAX_ENTRY_MACRO = 999;

const parseEntryAmount = (rawValue) => parseAmount(rawValue, { maxAbs: MAX_ENTRY_CALORIES });

const parseEntryMacroValue = (rawValue) => {
  if (rawValue === undefined) {
    return { provided: false, ok: true, value: null };
  }
  const normalized = String(rawValue ?? '').trim();
  if (normalized === '') {
    return { provided: true, ok: true, value: null };
  }
  const parsed = parseMacroInput(normalized);
  if (parsed === null || parsed > MAX_ENTRY_MACRO) {
    return { provided: true, ok: false, value: null };
  }
  return { provided: true, ok: true, value: parsed };
};

// Helper functions for dashboard data
function buildDayOptions(daysToShow) {
  // Use UTC to avoid timezone shifting when calculating date range
  const today = new Date();
  const todayStr = today.toISOString().slice(0, 10);
  
  // Calculate start date using UTC to avoid DST/timezone issues
  const startDate = new Date(todayStr + 'T00:00:00Z');
  startDate.setUTCDate(startDate.getUTCDate() - (daysToShow - 1));
  const startDateStr = startDate.toISOString().slice(0, 10);
  
  return buildDayOptionsBetween(startDateStr, todayStr);
}

function buildDayOptionsBetween(startDateStr, endDateStr) {
  const dayOptions = [];
  // Use UTC explicitly to avoid any timezone shifting
  const cursor = new Date(endDateStr + 'T00:00:00Z');
  const minDate = new Date(startDateStr + 'T00:00:00Z');
  
  for (let i = 0; i < MAX_HISTORY_DAYS; i += 1) {
    if (cursor < minDate) break;
    dayOptions.push(cursor.toISOString().slice(0, 10));
    cursor.setUTCDate(cursor.getUTCDate() - 1);
  }
  return dayOptions;
}

function getDateBounds(dayOptions) {
  return {
    newest: dayOptions[0],
    oldest: dayOptions[dayOptions.length - 1],
  };
}

function sanitizeDateRange(startStr, endStr, fallbackDays = DEFAULT_RANGE_DAYS, userTz = 'UTC') {
  const todayStr = formatDateInTz(new Date(), userTz);
  const requestedEnd = endStr && /^\d{4}-\d{2}-\d{2}$/.test(endStr.trim()) ? endStr.trim() : null;
  let endDateStr = requestedEnd && requestedEnd <= todayStr ? requestedEnd : todayStr;

  const requestedStart = startStr && /^\d{4}-\d{2}-\d{2}$/.test(startStr.trim()) ? startStr.trim() : null;

  // Calculate fallback start by subtracting days from end date
  const endDateObj = new Date(endDateStr + 'T12:00:00');
  const fallbackStartObj = new Date(endDateObj);
  fallbackStartObj.setDate(endDateObj.getDate() - (fallbackDays - 1));
  const fallbackStartStr = `${fallbackStartObj.getFullYear()}-${String(fallbackStartObj.getMonth() + 1).padStart(2, '0')}-${String(fallbackStartObj.getDate()).padStart(2, '0')}`;

  let startDateStr = requestedStart || fallbackStartStr;
  if (startDateStr > endDateStr) {
    startDateStr = endDateStr;
  }

  // Calculate max lookback
  const maxLookbackObj = new Date(endDateObj);
  maxLookbackObj.setDate(endDateObj.getDate() - (MAX_HISTORY_DAYS - 1));
  const maxLookbackStr = `${maxLookbackObj.getFullYear()}-${String(maxLookbackObj.getMonth() + 1).padStart(2, '0')}-${String(maxLookbackObj.getDate()).padStart(2, '0')}`;

  if (startDateStr < maxLookbackStr) {
    startDateStr = maxLookbackStr;
  }

  return { startDate: startDateStr, endDate: endDateStr };
}

async function getTotalsByDate(userId, oldestDate, newestDate) {
  const { rows } = await pool.query(
    `SELECT entry_date, SUM(amount) AS total
       FROM calorie_entries
      WHERE user_id = $1
        AND entry_date BETWEEN $2 AND $3
      GROUP BY entry_date
      ORDER BY entry_date DESC`,
    [userId, oldestDate, newestDate]
  );

  const totalsByDate = new Map();
  rows.forEach((row) => {
    totalsByDate.set(row.entry_date, parseInt(row.total, 10));
  });
  return totalsByDate;
}

function buildDailyStats(dayOptions, totalsByDate, dailyGoal, {
  macroTotalsByDate = null,
  enabledMacros = [],
  macroGoals = {},
  macroModes = {},
  threshold,
} = {}) {
  return dayOptions.map((dateStr) => {
    const total = totalsByDate.get(dateStr) || 0;
    const hasEntries = totalsByDate.has(dateStr);
    const statuses = [];

    // Calorie goal status (grey if no entries at all, otherwise evaluate against goal)
    if (dailyGoal) {
      if (!hasEntries) {
        statuses.push('zero');
      } else {
        const calStatus = computeMacroStatus(total, dailyGoal, macroModes.calories || 'limit', threshold);
        statuses.push(computeDotStatus(calStatus.statusClass));
      }
    }

    // Macro goal statuses (skip on days with no entries)
    if (hasEntries && macroTotalsByDate && enabledMacros.length > 0) {
      const dayMacros = macroTotalsByDate.get(dateStr) || {};
      for (const key of enabledMacros) {
        const goal = macroGoals[key] != null ? macroGoals[key] : null;
        if (goal == null || goal === 0) continue;
        const macroTotal = dayMacros[key] || 0;
        const ms = computeMacroStatus(macroTotal, goal, macroModes[key] || 'limit', threshold);
        statuses.push(computeDotStatus(ms.statusClass));
      }
    }

    let status;
    if (statuses.length === 0) {
      status = 'none';
    } else {
      status = worstDotStatus(statuses);
    }

    const overThreshold = status === 'over_threshold';
    return { date: dateStr, total, status, overThreshold };
  });
}

// Check AI availability
const { getEffectiveSetting } = require('../db/pool');
const { getAIUsageToday, getAIDailyLimit } = require('../lib/ai');

// Routes
router.get('/dashboard', requireLogin, async (req, res) => {
  const user = { ...req.currentUser, id: toInt(req.currentUser.id) };
  const userTimeZone = getUserTimezone(req, res);
  const serverNow = new Date();
  const todayStrTz = formatDateInTz(serverNow, userTimeZone);
  const requestedRange = parseInt(req.query.range, 10);
  const requestedDays = Number.isInteger(requestedRange)
    ? Math.min(Math.max(requestedRange, 7), MAX_HISTORY_DAYS)
    : DEFAULT_RANGE_DAYS;
  const ignoreCustomRange = Number.isInteger(requestedRange);
  const startParam = ignoreCustomRange ? null : req.query.start;
  const endParam = ignoreCustomRange ? null : req.query.end;
  const { startDate, endDate } = sanitizeDateRange(startParam, endParam, requestedDays, userTimeZone);
  const dayOptions = buildDayOptionsBetween(startDate, endDate);
  if (dayOptions.length === 0) {
    const fallbackToday = formatDateInTz(new Date(), userTimeZone);
    dayOptions.push(fallbackToday);
  }
  const { oldest, newest } = getDateBounds(dayOptions);
  const todayStr = formatDateInTz(new Date(), userTimeZone);
  const requestedDate = (req.query.day || '').trim();
  const selectedDate = dayOptions.includes(requestedDate)
    ? requestedDate
    : dayOptions.includes(todayStr)
    ? todayStr
    : newest;

  const totalsByDate = await getTotalsByDate(user.id, oldest, newest);
  const todayTotal = totalsByDate.get(todayStr) || 0;
  const macroModes = getMacroModes(user);
  const enabledMacros = getEnabledMacros(user);
  const macroGoals = getMacroGoals(user);
  const macroTotalsByDate = enabledMacros.length > 0 ? await getMacroTotalsByDate(user.id, oldest, newest) : new Map();
  const todayMacroTotals = macroTotalsByDate.get(todayStr) || {};
  const userThreshold = user.goal_threshold;

  const dailyGoal = getCalorieGoal(user);

  const dailyStats = buildDailyStats(dayOptions, totalsByDate, dailyGoal, {
    macroTotalsByDate,
    enabledMacros,
    macroGoals,
    macroModes,
    threshold: userThreshold,
  });

  // Calories are enabled unless explicitly disabled (backward compat: missing key = enabled)
  const caloriesEnabled = (user.macros_enabled || {}).calories !== false;
  const autoCalcCalories = isAutoCalcCalories(user);

  // Compute calorie status using the unified function
  const calorieStatus = caloriesEnabled ? computeMacroStatus(todayTotal, dailyGoal, macroModes.calories, userThreshold) : { statusClass: '', statusText: '' };
  // Keep backward-compat goalStatus/goalDelta for today panel
  const goalStatus = !dailyGoal
    ? 'unset'
    : todayTotal <= dailyGoal
      ? 'under'
      : computeMacroStatus(todayTotal, dailyGoal, 'limit', userThreshold).statusClass === 'macro-stat--danger'
        ? 'over_threshold'
        : 'over';
  const goalDelta = dailyGoal ? Math.abs(dailyGoal - todayTotal) : null;

  const { rows: recentEntries } = await pool.query(
    'SELECT id, entry_date, amount, entry_name, created_at, protein_g, carbs_g, fat_g, fiber_g, sugar_g FROM calorie_entries WHERE user_id = $1 AND entry_date = $2 ORDER BY created_at DESC',
    [user.id, selectedDate]
  );
  const viewEntries = recentEntries.map((entry) => ({
    ...entry,
    timeFormatted: entry.created_at ? formatTimeInTz(entry.created_at, userTimeZone) : '',
  }));

  // Compute per-macro statuses
  const macroStatuses = {};
  for (const key of enabledMacros) {
    const total = todayMacroTotals[key] || 0;
    const goal = macroGoals[key] != null ? macroGoals[key] : null;
    macroStatuses[key] = computeMacroStatus(total, goal, macroModes[key], userThreshold);
  }

  let acceptedLinks = [];
  try {
    acceptedLinks = await getAcceptedLinkUsers(user.id);
  } catch (err) {
    console.error('Failed to load linked users', err);
  }

  let weightEntry = null;
  let lastWeightEntry = null;
  try {
    weightEntry = await getWeightEntry(user.id, selectedDate);
    lastWeightEntry = await getLastWeightEntry(user.id, selectedDate);
  } catch (err) {
    console.error('Failed to load weight entry', err);
  }
  const weightTimeFormatted =
    weightEntry && (weightEntry.updated_at || weightEntry.created_at)
      ? formatTimeInTz(weightEntry.updated_at || weightEntry.created_at, userTimeZone)
      : '';
  const viewWeight = weightEntry ? { ...weightEntry, timeFormatted: weightTimeFormatted } : null;

  const sharedViews = [
    {
      userId: user.id,
      email: user.email,
      label: 'You',
      isSelf: true,
      dailyGoal,
      goalThreshold: userThreshold,
      dailyStats,
      todayStr: todayStrTz,
    },
  ];

  for (const link of acceptedLinks) {
    try {
      // Get the linked user's "today" in their timezone
      const linkTodayStr = formatDateInTz(new Date(), link.timezone);
      // Filter out days that haven't started yet in the linked user's timezone
      const linkDayOptions = dayOptions.filter((d) => d <= linkTodayStr);
      const linkOldest = linkDayOptions.length > 0 ? linkDayOptions[linkDayOptions.length - 1] : oldest;
      const linkNewest = linkDayOptions.length > 0 ? linkDayOptions[0] : newest;

      const linkGoal = getCalorieGoal(link);
      const totals = await getTotalsByDate(link.userId, linkOldest, linkNewest);
      const linkThreshold = link.goal_threshold;
      const linkEnabledMacros = getEnabledMacros(link);
      const linkMacroGoals = getMacroGoals(link);
      const linkMacroModes = getMacroModes(link);
      const linkMacroTotals = linkEnabledMacros.length > 0
        ? await getMacroTotalsByDate(link.userId, linkOldest, linkNewest)
        : null;
      const stats = buildDailyStats(linkDayOptions, totals, linkGoal, {
        macroTotalsByDate: linkMacroTotals,
        enabledMacros: linkEnabledMacros,
        macroGoals: linkMacroGoals,
        macroModes: linkMacroModes,
        threshold: linkThreshold,
      });
      sharedViews.push({
        linkId: link.linkId,
        userId: link.userId,
        email: link.email,
        label: (link.label || '').trim() || link.email,
        isSelf: false,
        dailyGoal: linkGoal,
        goalThreshold: linkThreshold,
        dailyStats: stats,
        todayStr: linkTodayStr,
      });
    } catch (err) {
      console.error('Failed to build stats for linked user', err);
    }
  }

  // Check if AI estimation is enabled (user or global API key)
  let hasAiEnabled = false;
  let aiUsingGlobalKey = false;
  let aiProviderName = null;

  const userProvider = user.preferred_ai_provider;
  const [globalKey, globalProvider] = await Promise.all([
    getEffectiveSetting('ai_key', process.env.AI_KEY),
    getEffectiveSetting('ai_provider', process.env.AI_PROVIDER),
  ]);

  if (user.ai_key) {
    hasAiEnabled = true;
    aiProviderName = userProvider || globalProvider.value || 'openai';
  } else {
    // AI is enabled if provider is set and requirements are met
    if (globalProvider.value) {
      if (globalProvider.value === 'ollama') {
        // Ollama just needs to be configured
        hasAiEnabled = true;
        aiUsingGlobalKey = true;
        aiProviderName = 'ollama';
      } else if (globalKey.value) {
        // OpenAI/Claude need API key
        hasAiEnabled = true;
        aiUsingGlobalKey = true;
        aiProviderName = globalProvider.value;
      }
    }
  }

  // Get AI usage info
  let aiUsage = null;
  if (hasAiEnabled) {
    if (aiUsingGlobalKey) {
      const dailyLimit = await getAIDailyLimit();
      if (dailyLimit !== null) {
        const usageToday = await getAIUsageToday(user.id);
        aiUsage = {
          used: usageToday,
          limit: dailyLimit,
          remaining: Math.max(0, dailyLimit - usageToday),
        };
      }
    } else if (user.ai_daily_limit) {
      const userLimit = parseInt(user.ai_daily_limit, 10);
      if (!Number.isNaN(userLimit) && userLimit > 0) {
        const usageToday = await getAIUsageToday(user.id);
        aiUsage = {
          used: usageToday,
          limit: userLimit,
          remaining: Math.max(0, userLimit - usageToday),
        };
      }
    }
  }

  res.render('dashboard', {
    user,
    dailyGoal,
    todayTotal,
    goalStatus,
    goalDelta,
    dailyStats,
    dayOptions,
    selectedDate,
    recentEntries: viewEntries,
    sharedViews,
    weightUnit: user.weight_unit || 'kg',
    timeZone: userTimeZone,
    todayStr: todayStrTz,
    range: {
      start: oldest,
      end: newest,
      days: dayOptions.length,
      preset: !req.query.start && !req.query.end ? requestedDays : null,
    },
    weightEntry: viewWeight,
    lastWeightEntry,
    hasAiEnabled,
    aiUsage,
    aiProviderName,
    activePage: 'dashboard',
    // Macro tracking data
    caloriesEnabled,
    autoCalcCalories,
    enabledMacros,
    macroGoals,
    todayMacroTotals,
    macroLabels: MACRO_LABELS,
    macroModes,
    macroStatuses,
    calorieStatus,
  });
});

router.get('/overview', requireLogin, requireLinkAuth, async (req, res) => {
  const requestedRange = parseInt(req.query.range, 10);
  const rangeDays = Number.isInteger(requestedRange)
    ? Math.min(Math.max(requestedRange, 7), MAX_HISTORY_DAYS)
    : DEFAULT_RANGE_DAYS;

  // Use values set by requireLinkAuth middleware
  const targetUserId = req.targetUserId;
  const targetUser = req.targetUser;

  // Use viewer's timezone for building the date range
  const viewerTz = getUserTimezone(req, res);
  // Use target user's timezone to determine their "today"
  const targetTz = targetUser?.timezone || 'UTC';

  const { startDate, endDate } = sanitizeDateRange(req.query.start, req.query.end, rangeDays, viewerTz);
  let dayOptions = buildDayOptionsBetween(startDate, endDate);

  // For linked users, filter out days that haven't started yet in their timezone
  if (targetUserId !== req.currentUser.id) {
    const targetTodayStr = formatDateInTz(new Date(), targetTz);
    dayOptions = dayOptions.filter((d) => d <= targetTodayStr);
  }

  if (dayOptions.length === 0) {
    const fallbackToday = formatDateInTz(new Date(), targetTz);
    dayOptions.push(fallbackToday);
  }
  const { oldest, newest } = getDateBounds(dayOptions);
  const todayStrTz = formatDateInTz(new Date(), targetTz);

  try {
    const dailyGoal = getCalorieGoal(targetUser);
    const totalsByDate = await getTotalsByDate(targetUserId, oldest, newest);
    const todayTotal = totalsByDate.get(todayStrTz) || 0;
    const isSelf = targetUserId === req.currentUser.id;
    const effectiveThreshold = isSelf ? req.currentUser.goal_threshold : targetUser.goal_threshold;

    // Use the target user's macro settings for dot status (so linked user dots match their own view)
    const targetEnabledMacros = getEnabledMacros(targetUser);
    const targetModes = getMacroModes(targetUser);
    const targetGoals = getMacroGoals(targetUser);
    let todayMacroTotals = null;
    let macroStatuses = null;
    let calorieStatusObj = null;
    let macroTotalsByDate = null;

    const targetCalEnabled = (targetUser.macros_enabled || {}).calories !== false;
    if (targetEnabledMacros.length > 0) {
      macroTotalsByDate = await getMacroTotalsByDate(targetUserId, oldest, newest);
      todayMacroTotals = macroTotalsByDate.get(todayStrTz) || {};
    }

    if (isSelf) {
      calorieStatusObj = targetCalEnabled ? computeMacroStatus(todayTotal, dailyGoal, targetModes.calories, effectiveThreshold) : null;
      if (targetEnabledMacros.length > 0) {
        macroStatuses = {};
        for (const key of targetEnabledMacros) {
          const total = todayMacroTotals[key] || 0;
          const goal = targetGoals[key] != null ? targetGoals[key] : null;
          macroStatuses[key] = computeMacroStatus(total, goal, targetModes[key], effectiveThreshold);
        }
      }
    }

    // Build daily stats — always include target user's macro data for accurate dot colors
    const dailyStats = buildDailyStats(dayOptions, totalsByDate, dailyGoal, {
      macroTotalsByDate,
      enabledMacros: targetEnabledMacros,
      macroGoals: targetGoals,
      macroModes: targetModes,
      threshold: effectiveThreshold,
    });

    const goalStatus = !dailyGoal
      ? 'unset'
      : todayTotal <= dailyGoal
        ? 'under'
        : computeMacroStatus(todayTotal, dailyGoal, 'limit', effectiveThreshold).statusClass === 'macro-stat--danger'
          ? 'over_threshold'
          : 'over';
    const goalDelta = dailyGoal ? Math.abs(dailyGoal - todayTotal) : null;

    return res.json({
      ok: true,
      userId: targetUserId,
      dailyGoal,
      goalThreshold: effectiveThreshold,
      todayTotal,
      todayStr: todayStrTz,
      goalStatus,
      goalDelta,
      dailyStats,
      dayOptions,
      range: { start: oldest, end: newest },
      todayMacroTotals,
      macroStatuses,
      calorieStatus: calorieStatusObj,
    });
  } catch (err) {
    console.error('Failed to build overview', err);
    return res.status(500).json({ ok: false, error: 'Failed to load overview' });
  }
});

router.get('/entries/day', requireLogin, requireLinkAuth, async (req, res) => {
  const dateStr = (req.query.date || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
    return res.status(400).json({ ok: false, error: 'Invalid date' });
  }

  // Use values set by requireLinkAuth middleware
  const targetUserId = req.targetUserId;
  const targetUser = req.targetUser;

  // Use viewer's timezone for date range validation (matches the dots shown in UI)
  const viewerTz = getUserTimezone(req, res);
  // Use target user's timezone for displaying entry timestamps
  const displayTz = targetUserId === req.currentUser.id
    ? viewerTz
    : (targetUser?.timezone || 'UTC');

  const today = new Date();
  const oldest = new Date(today);
  oldest.setDate(today.getDate() - (MAX_HISTORY_DAYS - 1));
  const oldestStr = formatDateInTz(oldest, viewerTz);
  const todayStr = formatDateInTz(today, viewerTz);

  if (dateStr < oldestStr || dateStr > todayStr) {
    return res.status(400).json({ ok: false, error: `Date must be within the last ${MAX_HISTORY_DAYS} days` });
  }

  try {
    const { rows } = await pool.query(
      'SELECT id, entry_date, amount, entry_name, created_at, protein_g, carbs_g, fat_g, fiber_g, sugar_g FROM calorie_entries WHERE user_id = $1 AND entry_date = $2 ORDER BY created_at DESC',
      [targetUserId, dateStr]
    );

    // Use the entry owner's enabled macros (so linked users see what the owner tracks)
    const ownerEnabledMacros = getEnabledMacros(targetUser);

    return res.json({
      ok: true,
      date: dateStr,
      entries: rows.map((row) => {
        const macros = {};
        for (const key of ownerEnabledMacros) {
          macros[key] = row[`${key}_g`];
        }
        return {
          id: row.id,
          date: row.entry_date,
          time: row.created_at ? formatTimeInTz(row.created_at, displayTz) : '',
          amount: row.amount,
          name: row.entry_name || null,
          macros: Object.keys(macros).length > 0 ? macros : null,
        };
      }),
    });
  } catch (err) {
    console.error('Failed to fetch entries for date', err);
    return res.status(500).json({ ok: false, error: 'Failed to load entries' });
  }
});

router.post('/entries', requireLogin, csrfProtection, async (req, res) => {
  const wantsJson = (req.headers.accept || '').includes('application/json');
  const userTz = getUserTimezone(req, res);
  const rawAmountInput = String(req.body.amount ?? '').trim();
  let { value: amount, ok: amountOk } = parseEntryAmount(req.body.amount);
  const { ok: weightOk, value: weightVal } = parseWeight(req.body.weight);
  const entryDate = req.body.entry_date || formatDateInTz(new Date(), userTz);
  const entryName = (req.body.entry_name || '').trim();
  const entryNameSafe = entryName ? entryName.slice(0, 120) : null;

  let hasCalorieEntry = amountOk && amount !== 0;
  const hasWeight = weightOk && weightVal !== null;

  // Parse macro values (save any that are provided, regardless of enabled state)
  const macroValues = {};
  let invalidMacroInput = false;
  for (const key of MACRO_KEYS) {
    const parsed = parseEntryMacroValue(req.body[`${key}_g`]);
    if (!parsed.ok) {
      invalidMacroInput = true;
      continue;
    }
    if (parsed.value !== null) {
      macroValues[key] = parsed.value;
    }
  }
  if (invalidMacroInput) {
    if (wantsJson) {
      return res.status(400).json({ ok: false, error: `Macro values must be between 0 and ${MAX_ENTRY_MACRO}` });
    }
    return res.redirect('/dashboard');
  }
  const hasMacroEntry = Object.keys(macroValues).length > 0;

  // Auto-calculate calories from macros when enabled
  if (isAutoCalcCalories(req.currentUser) && hasMacroEntry) {
    const computedCals = computeCaloriesFromMacros(
      macroValues.protein ?? 0,
      macroValues.carbs ?? 0,
      macroValues.fat ?? 0
    );
    if (computedCals !== null && computedCals > 0) {
      amount = computedCals;
      amountOk = true;
      hasCalorieEntry = true;
    }
  }

  if (rawAmountInput && !amountOk) {
    if (wantsJson) {
      return res.status(400).json({ ok: false, error: `Calories must be between -${MAX_ENTRY_CALORIES} and ${MAX_ENTRY_CALORIES}` });
    }
    return res.redirect('/dashboard');
  }

  if (!hasCalorieEntry && !hasMacroEntry && !hasWeight) {
    if (wantsJson) {
      return res.status(400).json({ ok: false, error: 'Invalid entry data' });
    }
    return res.redirect('/dashboard');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (hasCalorieEntry || hasMacroEntry) {
      // Use provided calorie amount, or 0 if only macros were provided
      const entryAmount = hasCalorieEntry ? amount : 0;
      // Build dynamic query for macros
      const macroKeys = Object.keys(macroValues);
      const macroColumns = macroKeys.length > 0 ? ', ' + macroKeys.map(k => `${k}_g`).join(', ') : '';
      const macroPlaceholders = macroKeys.length > 0 ? ', ' + macroKeys.map((_, i) => `$${5 + i}`).join(', ') : '';
      const macroVals = macroKeys.map(k => macroValues[k]);

      await client.query(
        `INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name${macroColumns}) VALUES ($1, $2, $3, $4${macroPlaceholders})`,
        [req.currentUser.id, entryDate, entryAmount, entryNameSafe, ...macroVals]
      );
    }

    if (hasWeight) {
      await upsertWeightEntry(req.currentUser.id, entryDate, weightVal, client.query.bind(client));
    }

    await client.query('COMMIT');

    if (hasCalorieEntry || hasMacroEntry) {
      await broadcastEntryChange(req.currentUser.id);
    }

    if (wantsJson) {
      return res.json({ ok: true });
    }
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Failed to add entry', err);
    if (wantsJson) {
      return res.status(500).json({ ok: false, error: 'Failed to save entry' });
    }
  } finally {
    client.release();
  }

  const dayParam = entryDate && /^\d{4}-\d{2}-\d{2}$/.test(entryDate) ? `?day=${entryDate}` : '';
  res.redirect(`/dashboard${dayParam}`);
});

router.post('/entries/:id/update', requireLogin, csrfProtection, async (req, res) => {
  const entryId = parseInt(req.params.id, 10);
  const wantsJson = (req.headers.accept || '').includes('application/json');
  const tz = getUserTimezone(req, res);

  if (Number.isNaN(entryId)) {
    return wantsJson ? res.status(400).json({ ok: false, error: 'Invalid entry id' }) : res.redirect('/dashboard');
  }

  const updates = [];
  const values = [];
  let idx = 1;

  if (req.body.name !== undefined) {
    const rawName = (req.body.name || '').toString().trim();
    const safeName = rawName ? rawName.slice(0, 120) : null;
    updates.push(`entry_name = $${idx}`);
    values.push(safeName);
    idx += 1;
  }

  const autoCalc = isAutoCalcCalories(req.currentUser);

  if (req.body.amount !== undefined && !autoCalc) {
    const { value: amount, ok } = parseEntryAmount(req.body.amount);
    if (!ok || amount === 0) {
      return wantsJson
        ? res.status(400).json({ ok: false, error: `Calories must be between -${MAX_ENTRY_CALORIES} and ${MAX_ENTRY_CALORIES}` })
        : res.redirect('/dashboard');
    }
    updates.push(`amount = $${idx}`);
    values.push(amount);
    idx += 1;
  }

  // Handle macro updates
  for (const key of MACRO_KEYS) {
    const fieldName = `${key}_g`;
    if (req.body[fieldName] !== undefined) {
      const parsed = parseEntryMacroValue(req.body[fieldName]);
      if (!parsed.ok) {
        return wantsJson
          ? res.status(400).json({ ok: false, error: `Macro values must be between 0 and ${MAX_ENTRY_MACRO}` })
          : res.redirect('/dashboard');
      }
      updates.push(`${fieldName} = $${idx}`);
      values.push(parsed.value); // null clears the value
      idx += 1;
    }
  }

  if (updates.length === 0) {
    return wantsJson
      ? res.status(400).json({ ok: false, error: 'No updates provided' })
      : res.redirect('/dashboard');
  }

  try {
    const { rows } = await pool.query(
      `UPDATE calorie_entries SET ${updates.join(', ')} WHERE id = $${idx} AND user_id = $${idx + 1} RETURNING id, entry_date, amount, entry_name, created_at, protein_g, carbs_g, fat_g, fiber_g, sugar_g`,
      [...values, entryId, req.currentUser.id]
    );

    if (rows.length === 0) {
      return wantsJson ? res.status(404).json({ ok: false, error: 'Entry not found' }) : res.redirect('/dashboard');
    }

    const updated = rows[0];

    // Recompute calories from macros when auto-calc is enabled
    if (autoCalc) {
      const computedCals = computeCaloriesFromMacros(
        updated.protein_g,
        updated.carbs_g,
        updated.fat_g
      );
      if (computedCals !== null) {
        await pool.query(
          'UPDATE calorie_entries SET amount = $1 WHERE id = $2 AND user_id = $3',
          [computedCals, entryId, req.currentUser.id]
        );
        updated.amount = computedCals;
      }
    }

    const userEnabledMacros = getEnabledMacros(req.currentUser);
    const macros = {};
    for (const key of userEnabledMacros) {
      macros[key] = updated[`${key}_g`];
    }
    const payload = {
      id: updated.id,
      date: updated.entry_date,
      time: updated.created_at ? formatTimeInTz(updated.created_at, tz) : '',
      amount: updated.amount,
      name: updated.entry_name || null,
      macros: Object.keys(macros).length > 0 ? macros : null,
    };

    await broadcastEntryChange(req.currentUser.id);

    if (wantsJson) {
      return res.json({ ok: true, entry: payload });
    }
  } catch (err) {
    console.error('Failed to update entry', err);
    if (wantsJson) {
      return res.status(500).json({ ok: false, error: 'Update failed' });
    }
  }

  return res.redirect('/dashboard');
});

router.post('/entries/:id/delete', requireLogin, csrfProtection, async (req, res) => {
  const entryId = parseInt(req.params.id, 10);
  const wantsJson = (req.headers.accept || '').includes('application/json');
  if (Number.isNaN(entryId)) {
    return wantsJson ? res.status(400).json({ ok: false }) : res.redirect('/dashboard');
  }

  try {
    await pool.query('DELETE FROM calorie_entries WHERE id = $1 AND user_id = $2', [
      entryId,
      req.currentUser.id,
    ]);
    await broadcastEntryChange(req.currentUser.id);
  } catch (err) {
    console.error('Failed to delete entry', err);
    if (wantsJson) {
      return res.status(500).json({ ok: false });
    }
  }

  if (wantsJson) {
    return res.json({ ok: true });
  }
  res.redirect('/dashboard');
});

// Import/Export
router.get('/settings/export', requireLogin, async (req, res) => {
  const user = req.currentUser;

  try {
    const { rows: entries } = await pool.query(
      'SELECT entry_date, amount, entry_name, created_at, protein_g, carbs_g, fat_g, fiber_g, sugar_g FROM calorie_entries WHERE user_id = $1 ORDER BY entry_date DESC, id DESC LIMIT 100000',
      [user.id]
    );

    const { rows: weights } = await pool.query(
      'SELECT entry_date, weight FROM weight_entries WHERE user_id = $1 ORDER BY entry_date DESC, id DESC LIMIT 100000',
      [user.id]
    );

    const filename = `schautrack-export-${new Date().toISOString().slice(0, 10)}.json`;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    // Stream JSON in chunks to avoid building one massive string in memory
    res.write('{\n');
    res.write(`"exported_at":${JSON.stringify(new Date().toISOString())},\n`);
    res.write(`"user":${JSON.stringify({
      email: user.email,
      daily_goal: getCalorieGoal(user),
      macros_enabled: user.macros_enabled || {},
      macro_goals: user.macro_goals || {},
      weight_unit: user.weight_unit || 'kg',
      timezone: user.timezone || null,
    })},\n`);

    // Write weights
    res.write('"weights":[');
    for (let i = 0; i < weights.length; i++) {
      if (i > 0) res.write(',');
      const row = weights[i];
      res.write(JSON.stringify({
        date: row.entry_date,
        weight: Number(row.weight),
      }));
    }
    res.write('],\n');

    // Write entries
    res.write('"entries":[');
    for (let i = 0; i < entries.length; i++) {
      if (i > 0) res.write(',');
      const row = entries[i];
      const entry = {
        date: row.entry_date,
        amount: row.amount,
        name: row.entry_name || null,
        created_at: row.created_at ? row.created_at.toISOString() : null,
      };
      if (row.protein_g != null) entry.protein_g = row.protein_g;
      if (row.carbs_g != null) entry.carbs_g = row.carbs_g;
      if (row.fat_g != null) entry.fat_g = row.fat_g;
      if (row.fiber_g != null) entry.fiber_g = row.fiber_g;
      if (row.sugar_g != null) entry.sugar_g = row.sugar_g;
      res.write(JSON.stringify(entry));
    }
    res.write(']\n');

    res.write('}');
    res.end();
  } catch (err) {
    console.error('Export failed', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Export failed' });
    } else {
      res.end();
    }
  }
});

router.post('/settings/import', requireLogin, upload.single('import_file'), csrfProtection, async (req, res) => {
  if (!req.file || !req.file.buffer) {
    return res.redirect('/settings');
  }

  let parsed;
  try {
    const raw = req.file.buffer.toString('utf8');
    parsed = JSON.parse(raw);
  } catch (err) {
    return res.redirect('/settings');
  }

  // Support old exports (daily_goal at top level or in user object) and new (macro_goals.calories)
  const goalCandidate =
    parsed.user?.macro_goals?.calories !== undefined ? parsed.user.macro_goals.calories
    : parsed.daily_goal !== undefined ? parsed.daily_goal
    : parsed.user?.daily_goal;
  const entries = Array.isArray(parsed.entries) ? parsed.entries.slice(0, 10000) : [];
  const weights = Array.isArray(parsed.weights) ? parsed.weights.slice(0, 10000) : [];

  const toInsert = [];
  entries.forEach((entry) => {
    const dateStr = (entry.date || entry.entry_date || '').toString();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return;
    const { value: amount, ok } = parseEntryAmount(entry.amount);
    if (!ok || amount === 0) return;
    const nameRaw = entry.name || entry.entry_name || '';
    const nameSafe = nameRaw ? String(nameRaw).trim().slice(0, 120) : null;
    const createdAt = entry.created_at ? new Date(entry.created_at) : null;
    // Parse macro values from import
    const proteinParsed = parseEntryMacroValue(entry.protein_g);
    const carbsParsed = parseEntryMacroValue(entry.carbs_g);
    const fatParsed = parseEntryMacroValue(entry.fat_g);
    const fiberParsed = parseEntryMacroValue(entry.fiber_g);
    const sugarParsed = parseEntryMacroValue(entry.sugar_g);
    const protein_g = proteinParsed.ok ? proteinParsed.value : null;
    const carbs_g = carbsParsed.ok ? carbsParsed.value : null;
    const fat_g = fatParsed.ok ? fatParsed.value : null;
    const fiber_g = fiberParsed.ok ? fiberParsed.value : null;
    const sugar_g = sugarParsed.ok ? sugarParsed.value : null;
    toInsert.push({ date: dateStr, amount, name: nameSafe, created_at: createdAt, protein_g, carbs_g, fat_g, fiber_g, sugar_g });
  });

  const weightToInsert = [];
  weights.forEach((entry) => {
    const dateStr = (entry.date || entry.entry_date || '').toString();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return;
    const { ok: weightOk, value: weightVal } = parseWeight(entry.weight);
    if (!weightOk || weightVal === null) return;
    weightToInsert.push({ date: dateStr, weight: weightVal });
  });

  // Check if the file has user settings worth importing
  const hasUserSettings = parsed.user && (
    parsed.user.macros_enabled || parsed.user.macro_goals || goalCandidate != null ||
    parsed.user.weight_unit || parsed.user.timezone
  );

  // Validate that we have at least some valid data before deleting existing data
  if (toInsert.length === 0 && weightToInsert.length === 0 && !hasUserSettings) {
    req.session.importFeedback = { type: 'error', message: 'No valid entries found in import file.' };
    return res.redirect('/settings');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (toInsert.length > 0) {
      await client.query('DELETE FROM calorie_entries WHERE user_id = $1', [req.currentUser.id]);
    }
    if (weightToInsert.length > 0) {
      await client.query('DELETE FROM weight_entries WHERE user_id = $1', [req.currentUser.id]);
    }
    // Import macro preferences if present (validate keys against known macros)
    const importedMacrosEnabled = parsed.user?.macros_enabled;
    const importedMacroGoals = parsed.user?.macro_goals;
    if (importedMacrosEnabled || importedMacroGoals || (Number.isInteger(goalCandidate) && goalCandidate >= 0)) {
      const validToggleKeys = [...MACRO_KEYS, 'calories', 'auto_calc_calories'];
      const validGoalKeys = ['calories', ...MACRO_KEYS.map(k => k), ...MACRO_KEYS.map(k => `${k}_mode`), 'calories_mode'];

      const macrosEnabled = {};
      if (importedMacrosEnabled && typeof importedMacrosEnabled === 'object') {
        for (const key of validToggleKeys) {
          if (key in importedMacrosEnabled && typeof importedMacrosEnabled[key] === 'boolean') {
            macrosEnabled[key] = importedMacrosEnabled[key];
          }
        }
      }
      const macroGoalsImport = {};
      if (importedMacroGoals && typeof importedMacroGoals === 'object') {
        for (const key of validGoalKeys) {
          const val = importedMacroGoals[key];
          if (key.endsWith('_mode')) {
            if (val === 'limit' || val === 'target') macroGoalsImport[key] = val;
          } else if (Number.isInteger(val) && val >= 0) {
            macroGoalsImport[key] = val;
          }
        }
      }
      // Ensure calorie goal from old-format exports (daily_goal) gets stored in macro_goals
      if (macroGoalsImport.calories == null && Number.isInteger(goalCandidate) && goalCandidate >= 0) {
        macroGoalsImport.calories = goalCandidate;
      }
      await client.query('UPDATE users SET macros_enabled = $1, macro_goals = $2 WHERE id = $3', [
        JSON.stringify(macrosEnabled),
        JSON.stringify(macroGoalsImport),
        req.currentUser.id,
      ]);
    }

    // Import weight_unit and timezone if present
    const importedWeightUnit = parsed.user?.weight_unit;
    const importedTimezone = parsed.user?.timezone;
    if (importedWeightUnit && ['kg', 'lb'].includes(importedWeightUnit)) {
      await client.query('UPDATE users SET weight_unit = $1 WHERE id = $2', [importedWeightUnit, req.currentUser.id]);
    }
    if (importedTimezone && typeof importedTimezone === 'string' && importedTimezone.length <= 50) {
      await client.query('UPDATE users SET timezone = $1, timezone_manual = TRUE WHERE id = $2', [importedTimezone, req.currentUser.id]);
    }

    for (const entry of toInsert) {
      if (entry.created_at) {
        await client.query(
          'INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name, created_at, protein_g, carbs_g, fat_g, fiber_g, sugar_g) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)',
          [req.currentUser.id, entry.date, entry.amount, entry.name, entry.created_at, entry.protein_g, entry.carbs_g, entry.fat_g, entry.fiber_g, entry.sugar_g]
        );
      } else {
        await client.query(
          'INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name, protein_g, carbs_g, fat_g, fiber_g, sugar_g) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
          [req.currentUser.id, entry.date, entry.amount, entry.name, entry.protein_g, entry.carbs_g, entry.fat_g, entry.fiber_g, entry.sugar_g]
        );
      }
    }
    for (const w of weightToInsert) {
      await upsertWeightEntry(req.currentUser.id, w.date, w.weight, client.query.bind(client));
    }
    await client.query('COMMIT');
    const parts = [];
    if (toInsert.length > 0) parts.push(`${toInsert.length} entries`);
    if (weightToInsert.length > 0) parts.push(`${weightToInsert.length} weight records`);
    if (hasUserSettings) parts.push('user settings');
    req.session.importFeedback = { type: 'success', message: `Imported ${parts.join(' and ')}.` };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error('Import failed', err);
    req.session.importFeedback = { type: 'error', message: 'Import failed — the file may contain invalid data. Your existing entries were not changed.' };
  } finally {
    client.release();
  }

  res.redirect('/settings');
});

module.exports = router;
module.exports.buildDailyStats = buildDailyStats;
