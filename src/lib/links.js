const { pool } = require('../db/pool');
const { toInt } = require('./utils');

async function countAcceptedLinks(userId) {
  const uid = toInt(userId);
  if (uid === null) return 0;
  const { rows } = await pool.query(
    'SELECT COUNT(*) AS count FROM account_links WHERE status = $1 AND (requester_id = $2 OR target_id = $2)',
    ['accepted', uid]
  );
  return parseInt(rows[0]?.count || 0, 10);
}

async function getLinkBetween(userId, otherUserId) {
  const uid = toInt(userId);
  const oid = toInt(otherUserId);
  if (uid === null || oid === null) return null;
  const { rows } = await pool.query(
    `SELECT *
       FROM account_links
      WHERE LEAST(requester_id, target_id) = LEAST($1::int, $2::int)
        AND GREATEST(requester_id, target_id) = GREATEST($1::int, $2::int)
      LIMIT 1`,
    [uid, oid]
  );
  return rows[0] || null;
}

async function getLinkRequests(userId) {
  const uid = toInt(userId);
  if (uid === null) {
    return { incoming: [], outgoing: [], accepted: [] };
  }
  const { rows: incomingRows } = await pool.query(
    `SELECT al.id, al.created_at, u.email
       FROM account_links al
       JOIN users u ON u.id = al.requester_id
      WHERE al.target_id = $1
        AND al.status = 'pending'
      ORDER BY al.created_at DESC`,
    [uid]
  );

  const { rows: outgoingRows } = await pool.query(
    `SELECT al.id, al.created_at, u.email
       FROM account_links al
       JOIN users u ON u.id = al.target_id
      WHERE al.requester_id = $1
        AND al.status = 'pending'
      ORDER BY al.created_at DESC`,
    [uid]
  );

  const { rows: acceptedRows } = await pool.query(
    `SELECT al.id, al.created_at, u.email
       FROM account_links al
       JOIN users u ON u.id = CASE WHEN al.requester_id = $1 THEN al.target_id ELSE al.requester_id END
      WHERE al.status = 'accepted'
        AND ($1 = al.requester_id OR $1 = al.target_id)
      ORDER BY al.created_at DESC`,
    [uid]
  );

  return {
    incoming: incomingRows.map((row) => ({
      id: row.id,
      email: row.email,
      created_at: row.created_at,
    })),
    outgoing: outgoingRows.map((row) => ({
      id: row.id,
      email: row.email,
      created_at: row.created_at,
    })),
    accepted: acceptedRows.map((row) => ({
      id: row.id,
      email: row.email,
      created_at: row.created_at,
    })),
  };
}

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

module.exports = {
  countAcceptedLinks,
  getLinkBetween,
  getLinkRequests,
  getAcceptedLinkUsers,
};
