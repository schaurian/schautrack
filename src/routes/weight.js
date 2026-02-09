const express = require('express');
const { pool } = require('../db/pool');
const { requireLogin } = require('../middleware/auth');
const { requireLinkAuth } = require('../middleware/links');
const { parseWeight, getUserTimezone, formatDateInTz, toIsoDate } = require('../lib/utils');

const router = express.Router();

const MAX_HISTORY_DAYS = 180;

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
    date: toIsoDate(row.entry_date),
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
    date: toIsoDate(row.entry_date),
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
    date: toIsoDate(row.entry_date),
    weight: Number(row.weight),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

router.get('/weight/day', requireLogin, requireLinkAuth, async (req, res) => {
  const dateStr = (req.query.date || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
    return res.status(400).json({ ok: false, error: 'Invalid date' });
  }

  // Use values set by requireLinkAuth middleware
  const targetUserId = req.targetUserId;
  const targetUser = req.targetUser;

  // Use target user's timezone for linked users, viewer's timezone for self
  const tz = targetUserId === req.currentUser.id
    ? getUserTimezone(req, res)
    : (targetUser?.timezone || 'UTC');

  const today = new Date();
  const oldest = new Date(today);
  oldest.setDate(today.getDate() - (MAX_HISTORY_DAYS - 1));
  const oldestStr = formatDateInTz(oldest, tz);
  const todayStr = formatDateInTz(today, tz);

  if (dateStr < oldestStr || dateStr > todayStr) {
    return res.status(400).json({ ok: false, error: 'Date outside supported range' });
  }

  try {
    const entry = await getWeightEntry(targetUserId, dateStr);
    const lastWeight = await getLastWeightEntry(targetUserId, dateStr);
    return res.json({ ok: true, entry, lastWeight });
  } catch (err) {
    console.error('Failed to fetch weight entry', err);
    return res.status(500).json({ ok: false, error: 'Could not load weight' });
  }
});

router.post('/weight/upsert', requireLogin, async (req, res) => {
  const wantsJson = (req.headers.accept || '').includes('application/json');
  const userTz = getUserTimezone(req, res);
  const dateStr = (req.body.entry_date || req.body.date || '').trim() || formatDateInTz(new Date(), userTz);
  const { ok, value: weight } = parseWeight(req.body.weight);

  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
    return wantsJson
      ? res.status(400).json({ ok: false, error: 'Invalid date' })
      : res.redirect('/dashboard');
  }

  if (!ok || weight === null) {
    return wantsJson
      ? res.status(400).json({ ok: false, error: 'Invalid weight' })
      : res.redirect('/dashboard');
  }

  const today = new Date();
  const oldest = new Date(today);
  oldest.setDate(today.getDate() - (MAX_HISTORY_DAYS - 1));
  const oldestStr = formatDateInTz(oldest, userTz);
  const todayStr = formatDateInTz(today, userTz);
  if (dateStr < oldestStr || dateStr > todayStr) {
    return wantsJson
      ? res.status(400).json({ ok: false, error: 'Date outside supported range' })
      : res.redirect('/dashboard');
  }

  try {
    const entry = await upsertWeightEntry(req.currentUser.id, dateStr, weight);
    if (wantsJson) {
      return res.json({ ok: true, entry });
    }
  } catch (err) {
    console.error('Failed to upsert weight entry', err);
    if (wantsJson) {
      return res.status(500).json({ ok: false, error: 'Could not save weight' });
    }
  }

  return res.redirect('/dashboard');
});

router.post('/weight/:id/delete', requireLogin, async (req, res) => {
  const weightId = parseInt(req.params.id, 10);
  const wantsJson = (req.headers.accept || '').includes('application/json');
  if (Number.isNaN(weightId)) {
    return wantsJson ? res.status(400).json({ ok: false }) : res.redirect('/dashboard');
  }

  try {
    await pool.query('DELETE FROM weight_entries WHERE id = $1 AND user_id = $2', [
      weightId,
      req.currentUser.id,
    ]);
    // Note: Weight changes don't broadcast like calorie entries
  } catch (err) {
    console.error('Failed to delete weight entry', err);
    if (wantsJson) {
      return res.status(500).json({ ok: false });
    }
  }

  if (wantsJson) {
    return res.json({ ok: true });
  }
  res.redirect('/dashboard');
});

module.exports = router;