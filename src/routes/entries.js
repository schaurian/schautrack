const express = require('express');
const multer = require('multer');
const { pool } = require('../db/pool');
const { requireLogin } = require('../middleware/auth');
const { requireLinkAuth } = require('../middleware/links');
const { csrfProtection } = require('../middleware/csrf');
const { parseAmount } = require('../lib/math-parser');
const { 
  parseWeight, 
  toInt, 
  getUserTimezone, 
  formatDateInTz, 
  formatTimeInTz 
} = require('../lib/utils');

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
});

// Constants
const MAX_HISTORY_DAYS = 180;
const DEFAULT_RANGE_DAYS = 14;

// Helper functions for dashboard data
function buildDayOptions(daysToShow) {
  const today = new Date();
  const startDate = new Date(today);
  startDate.setDate(today.getDate() - (daysToShow - 1));
  return buildDayOptionsBetween(startDate, today);
}

function buildDayOptionsBetween(startDateStr, endDateStr) {
  const dayOptions = [];
  // Work with date strings directly to avoid timezone issues
  // Parse as local date by appending time component
  const cursor = new Date(endDateStr + 'T12:00:00');
  const minDate = new Date(startDateStr + 'T12:00:00');
  for (let i = 0; i < MAX_HISTORY_DAYS; i += 1) {
    if (cursor < minDate) break;
    // Format as YYYY-MM-DD without timezone conversion
    const year = cursor.getFullYear();
    const month = String(cursor.getMonth() + 1).padStart(2, '0');
    const day = String(cursor.getDate()).padStart(2, '0');
    dayOptions.push(`${year}-${month}-${day}`);
    cursor.setDate(cursor.getDate() - 1);
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
    const dateStr = row.entry_date.toISOString().slice(0, 10);
    totalsByDate.set(dateStr, parseInt(row.total, 10));
  });
  return totalsByDate;
}

function buildDailyStats(dayOptions, totalsByDate, dailyGoal) {
  const goalThreshold = dailyGoal ? Math.round(dailyGoal * 1.1) : null;
  return dayOptions.map((dateStr) => {
    const total = totalsByDate.get(dateStr) || 0;
    let status = 'none';
    let overThreshold = false;
    if (dailyGoal) {
      if (total === 0) {
        status = 'zero';
      } else if (total <= dailyGoal) {
        status = 'under';
      } else if (goalThreshold && total > goalThreshold) {
        status = 'over_threshold';
        overThreshold = true;
      } else {
        status = 'over';
      }
    }
    return { date: dateStr, total, status, overThreshold };
  });
}

// Weight helper functions
async function upsertWeightEntry(userId, dateStr, weight) {
  const { rows } = await pool.query(
    `INSERT INTO weight_entries (user_id, entry_date, weight)
       VALUES ($1, $2, $3)
      ON CONFLICT (user_id, entry_date)
        DO UPDATE SET weight = EXCLUDED.weight, updated_at = NOW()
      RETURNING id, entry_date, weight, created_at, updated_at`,
    [userId, dateStr, weight]
  );
  const row = rows[0];
  if (!row) return null;
  return {
    id: row.id,
    date: row.entry_date.toISOString().slice(0, 10),
    weight: Number(row.weight),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

async function getWeightEntry(userId, dateStr) {
  const { rows } = await pool.query(
    'SELECT id, entry_date, weight, created_at, updated_at FROM weight_entries WHERE user_id = $1 AND entry_date = $2 LIMIT 1',
    [userId, dateStr]
  );
  const row = rows[0];
  if (!row) return null;
  return {
    id: row.id,
    date: row.entry_date.toISOString().slice(0, 10),
    weight: Number(row.weight),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

async function getLastWeightEntry(userId, beforeOrOnDate = null) {
  let query = 'SELECT id, entry_date, weight, created_at, updated_at FROM weight_entries WHERE user_id = $1';
  const params = [userId];
  if (beforeOrOnDate) {
    query += ' AND entry_date <= $2';
    params.push(beforeOrOnDate);
  }
  query += ' ORDER BY entry_date DESC LIMIT 1';
  const { rows } = await pool.query(query, params);
  const row = rows[0];
  if (!row) return null;
  return {
    id: row.id,
    date: row.entry_date.toISOString().slice(0, 10),
    weight: Number(row.weight),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

// Account linking helpers
async function getAcceptedLinkUsers(userId) {
  const uid = toInt(userId);
  if (uid === null) return [];
  const { rows } = await pool.query(
    `SELECT al.id AS link_id,
            al.created_at,
            CASE WHEN al.requester_id = $1 THEN al.requester_label ELSE al.target_label END AS label,
            CASE WHEN al.requester_id = $1 THEN al.target_id ELSE al.requester_id END AS other_id,
            u.email AS other_email,
            u.daily_goal AS other_daily_goal,
            u.timezone AS other_timezone
       FROM account_links al
        JOIN users u ON u.id = CASE WHEN al.requester_id = $1 THEN al.target_id ELSE al.requester_id END
      WHERE al.status = 'accepted'
        AND ($1 = al.requester_id OR $1 = al.target_id)
      ORDER BY al.created_at DESC`,
    [uid]
  );

  return rows.map((row) => ({
    linkId: row.link_id,
    userId: row.other_id,
    label: row.label,
    email: row.other_email,
    daily_goal: row.other_daily_goal,
    timezone: row.other_timezone || 'UTC',
    since: row.created_at,
  }));
}

// SSE for real-time updates
const userEventClients = new Map(); // userId -> Set(res)

function addUserEventClient(userId, res) {
  if (!userEventClients.has(userId)) {
    userEventClients.set(userId, new Set());
  }
  userEventClients.get(userId).add(res);
}

function removeUserEventClient(userId, res) {
  const set = userEventClients.get(userId);
  if (!set) return;
  set.delete(res);
  if (set.size === 0) {
    userEventClients.delete(userId);
  }
}

function sendUserEvent(userId, eventName, payload) {
  const set = userEventClients.get(userId);
  if (!set || set.size === 0) return;
  const data = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
  const staleConnections = [];
  
  for (const res of set) {
    try {
      res.write(data);
    } catch (err) {
      // Connection is stale, mark for removal
      staleConnections.push(res);
    }
  }
  
  // Clean up stale connections
  for (const staleRes of staleConnections) {
    removeUserEventClient(userId, staleRes);
  }
}

async function broadcastEntryChange(sourceUserId) {
  const uid = toInt(sourceUserId);
  if (uid === null) return;
  const targets = new Set([uid]);
  try {
    const links = await getAcceptedLinkUsers(uid);
    links.forEach((link) => targets.add(link.userId));
  } catch (err) {
    console.error('Failed to load linked users for broadcast', err);
  }
  const payload = { sourceUserId: uid, at: Date.now() };
  targets.forEach((targetId) => sendUserEvent(targetId, 'entry-change', payload));
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
  const dailyStats = buildDailyStats(dayOptions, totalsByDate, user.daily_goal);

  const todayTotal = totalsByDate.get(todayStr) || 0;
  const goalThreshold = user.daily_goal ? Math.round(user.daily_goal * 1.1) : null;
  const goalStatus = !user.daily_goal
    ? 'unset'
    : todayTotal <= user.daily_goal
      ? 'under'
      : goalThreshold && todayTotal > goalThreshold
        ? 'over_threshold'
        : 'over';
  const goalDelta = user.daily_goal ? Math.abs(user.daily_goal - todayTotal) : null;

  const { rows: recentEntries } = await pool.query(
    'SELECT id, entry_date, amount, entry_name, created_at FROM calorie_entries WHERE user_id = $1 AND entry_date = $2 ORDER BY created_at DESC',
    [user.id, selectedDate]
  );
  const viewEntries = recentEntries.map((entry) => ({
    ...entry,
    timeFormatted: entry.created_at ? formatTimeInTz(entry.created_at, userTimeZone) : '',
  }));

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
      dailyGoal: user.daily_goal,
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

      const totals = await getTotalsByDate(link.userId, linkOldest, linkNewest);
      const stats = buildDailyStats(linkDayOptions, totals, link.daily_goal);
      sharedViews.push({
        linkId: link.linkId,
        userId: link.userId,
        email: link.email,
        label: (link.label || '').trim() || link.email,
        isSelf: false,
        dailyGoal: link.daily_goal,
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

  const userProvider = user.ai_provider;
  const globalKey = await getEffectiveSetting('ai_key', process.env.AI_KEY);
  const globalProvider = await getEffectiveSetting('ai_provider', process.env.AI_PROVIDER);

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

  // Get AI usage info if using global key
  let aiUsage = null;
  if (hasAiEnabled && aiUsingGlobalKey) {
    const dailyLimit = await getAIDailyLimit();
    if (dailyLimit !== null) {
      const usageToday = await getAIUsageToday(user.id);
      aiUsage = {
        used: usageToday,
        limit: dailyLimit,
        remaining: Math.max(0, dailyLimit - usageToday),
      };
    }
  }

  res.render('dashboard', {
    user,
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
    const dailyGoal = targetUser?.daily_goal || null;
    const totalsByDate = await getTotalsByDate(targetUserId, oldest, newest);
    const dailyStats = buildDailyStats(dayOptions, totalsByDate, dailyGoal);
    const todayTotal = totalsByDate.get(todayStrTz) || 0;
    const goalThreshold = dailyGoal ? Math.round(dailyGoal * 1.1) : null;
    const goalStatus = !dailyGoal
      ? 'unset'
      : todayTotal <= dailyGoal
        ? 'under'
        : goalThreshold && todayTotal > goalThreshold
          ? 'over_threshold'
          : 'over';
    const goalDelta = dailyGoal ? Math.abs(dailyGoal - todayTotal) : null;

    return res.json({
      ok: true,
      userId: targetUserId,
      dailyGoal,
      todayTotal,
      todayStr: todayStrTz,
      goalStatus,
      goalDelta,
      dailyStats,
      dayOptions,
      range: { start: oldest, end: newest },
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
    return res.status(400).json({ ok: false, error: 'Date must be within the last 14 days' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT id, entry_date, amount, entry_name, created_at FROM calorie_entries WHERE user_id = $1 AND entry_date = $2 ORDER BY created_at DESC',
      [targetUserId, dateStr]
    );

    return res.json({
      ok: true,
      date: dateStr,
      entries: rows.map((row) => ({
        id: row.id,
        date: row.entry_date.toISOString().slice(0, 10),
        time: row.created_at ? formatTimeInTz(row.created_at, displayTz) : '',
        amount: row.amount,
        name: row.entry_name || null,
      })),
    });
  } catch (err) {
    console.error('Failed to fetch entries for date', err);
    return res.status(500).json({ ok: false, error: 'Failed to load entries' });
  }
});

router.post('/entries', requireLogin, csrfProtection, async (req, res) => {
  const wantsJson = (req.headers.accept || '').includes('application/json');
  const userTz = getUserTimezone(req, res);
  const { value: amount, ok: amountOk } = parseAmount(req.body.amount);
  const { ok: weightOk, value: weightVal } = parseWeight(req.body.weight);
  const entryDate = req.body.entry_date || formatDateInTz(new Date(), userTz);
  const entryName = (req.body.entry_name || '').trim();
  const entryNameSafe = entryName ? entryName.slice(0, 120) : null;

  const hasCalorieEntry = amountOk && amount !== 0;
  const hasWeight = weightOk && weightVal !== null;

  if (!hasCalorieEntry && !hasWeight) {
    if (wantsJson) {
      return res.status(400).json({ ok: false, error: 'Invalid entry data' });
    }
    return res.redirect('/dashboard');
  }

  try {
    await pool.query('BEGIN');

    if (hasCalorieEntry) {
      await pool.query(
        'INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name) VALUES ($1, $2, $3, $4)',
        [req.currentUser.id, entryDate, amount, entryNameSafe]
      );
    }

    if (hasWeight) {
      await upsertWeightEntry(req.currentUser.id, entryDate, weightVal);
    }

    await pool.query('COMMIT');

    if (hasCalorieEntry) {
      await broadcastEntryChange(req.currentUser.id);
    }

    if (wantsJson) {
      return res.json({ ok: true });
    }
  } catch (err) {
    console.error('Failed to add entry', err);
    await pool.query('ROLLBACK').catch(() => {});
    if (wantsJson) {
      return res.status(500).json({ ok: false, error: 'Failed to save entry' });
    }
  }

  res.redirect('/dashboard');
});

router.post('/entries/:id/update', requireLogin, async (req, res) => {
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

  if (req.body.amount !== undefined) {
    const { value: amount, ok } = parseAmount(req.body.amount);
    if (!ok || amount === 0) {
      return wantsJson
        ? res.status(400).json({ ok: false, error: 'Invalid amount' })
        : res.redirect('/dashboard');
    }
    updates.push(`amount = $${idx}`);
    values.push(amount);
    idx += 1;
  }

  if (updates.length === 0) {
    return wantsJson
      ? res.status(400).json({ ok: false, error: 'No updates provided' })
      : res.redirect('/dashboard');
  }

  try {
    const { rows } = await pool.query(
      `UPDATE calorie_entries SET ${updates.join(', ')} WHERE id = $${idx} AND user_id = $${idx + 1} RETURNING id, entry_date, amount, entry_name, created_at`,
      [...values, entryId, req.currentUser.id]
    );

    if (rows.length === 0) {
      return wantsJson ? res.status(404).json({ ok: false, error: 'Entry not found' }) : res.redirect('/dashboard');
    }

    const updated = rows[0];
    const payload = {
      id: updated.id,
      date: updated.entry_date.toISOString().slice(0, 10),
      time: updated.created_at ? formatTimeInTz(updated.created_at, tz) : '',
      amount: updated.amount,
      name: updated.entry_name || null,
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

router.post('/entries/:id/delete', requireLogin, async (req, res) => {
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

router.post('/goal', requireLogin, async (req, res) => {
  const goal = parseInt(req.body.goal, 10);
  if (Number.isNaN(goal) || goal < 0) {
    return res.redirect('/settings');
  }

  try {
    await pool.query('UPDATE users SET daily_goal = $1 WHERE id = $2', [goal, req.currentUser.id]);
  } catch (err) {
    console.error('Failed to update goal', err);
  }

  res.redirect('/settings');
});

// Import/Export
router.get('/settings/export', requireLogin, async (req, res) => {
  const user = req.currentUser;
  const { rows: entries } = await pool.query(
    'SELECT entry_date, amount, entry_name, created_at FROM calorie_entries WHERE user_id = $1 ORDER BY entry_date DESC, id DESC',
    [user.id]
  );

  const { rows: weights } = await pool.query(
    'SELECT entry_date, weight FROM weight_entries WHERE user_id = $1 ORDER BY entry_date DESC, id DESC',
    [user.id]
  );

  const payload = {
    exported_at: new Date().toISOString(),
    user: {
      email: user.email,
      daily_goal: user.daily_goal,
    },
    weights: weights.map((row) => ({
      date: row.entry_date.toISOString().slice(0, 10),
      weight: Number(row.weight),
    })),
    entries: entries.map((row) => ({
      date: row.entry_date.toISOString().slice(0, 10),
      amount: row.amount,
      name: row.entry_name || null,
      created_at: row.created_at ? row.created_at.toISOString() : null,
    })),
  };

  const filename = `schautrack-export-${new Date().toISOString().slice(0, 10)}.json`;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(JSON.stringify(payload, null, 2));
});

router.post('/settings/import', requireLogin, upload.single('import_file'), async (req, res) => {
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

  const goalCandidate =
    parsed.daily_goal !== undefined ? parsed.daily_goal : parsed.user?.daily_goal;
  const entries = Array.isArray(parsed.entries) ? parsed.entries.slice(0, 500) : [];
  const weights = Array.isArray(parsed.weights) ? parsed.weights.slice(0, 500) : [];

  const toInsert = [];
  entries.forEach((entry) => {
    const dateStr = (entry.date || entry.entry_date || '').toString();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return;
    const { value: amount, ok } = parseAmount(entry.amount);
    if (!ok || amount === 0) return;
    const nameRaw = entry.name || entry.entry_name || '';
    const nameSafe = nameRaw ? String(nameRaw).trim().slice(0, 120) : null;
    const createdAt = entry.created_at ? new Date(entry.created_at) : null;
    toInsert.push({ date: dateStr, amount, name: nameSafe, created_at: createdAt });
  });

  const weightToInsert = [];
  weights.forEach((entry) => {
    const dateStr = (entry.date || entry.entry_date || '').toString();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return;
    const { ok: weightOk, value: weightVal } = parseWeight(entry.weight);
    if (!weightOk || weightVal === null) return;
    weightToInsert.push({ date: dateStr, weight: weightVal });
  });

  try {
    await pool.query('BEGIN');
    await pool.query('DELETE FROM calorie_entries WHERE user_id = $1', [req.currentUser.id]);
    await pool.query('DELETE FROM weight_entries WHERE user_id = $1', [req.currentUser.id]);
    if (Number.isInteger(goalCandidate) && goalCandidate >= 0) {
      await pool.query('UPDATE users SET daily_goal = $1 WHERE id = $2', [
        goalCandidate,
        req.currentUser.id,
      ]);
    }

    for (const entry of toInsert) {
      if (entry.created_at) {
        await pool.query(
          'INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name, created_at) VALUES ($1, $2, $3, $4, $5)',
          [req.currentUser.id, entry.date, entry.amount, entry.name, entry.created_at]
        );
      } else {
        await pool.query(
          'INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name) VALUES ($1, $2, $3, $4)',
          [req.currentUser.id, entry.date, entry.amount, entry.name]
        );
      }
    }
    for (const w of weightToInsert) {
      await upsertWeightEntry(req.currentUser.id, w.date, w.weight);
    }
    await pool.query('COMMIT');
  } catch (err) {
    console.error('Import failed', err);
    await pool.query('ROLLBACK');
  }

  res.redirect('/settings');
});

module.exports = router;