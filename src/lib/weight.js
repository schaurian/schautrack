const { pool } = require('../db/pool');
const { toIsoDate } = require('./utils');

async function upsertWeightEntry(userId, dateStr, weight, queryFn) {
  const query = queryFn || pool.query.bind(pool);
  const { rows } = await query(
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

module.exports = {
  upsertWeightEntry,
  getWeightEntry,
  getLastWeightEntry,
};
