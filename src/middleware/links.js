const { pool } = require('../db/pool');
const { getUserById } = require('./auth');

// Middleware to handle link authorization for routes with ?user= parameter
const requireLinkAuth = async (req, res, next) => {
  const targetUserIdRaw = req.query.user ? parseInt(req.query.user, 10) : req.currentUser.id;
  const targetUserId = Number.isNaN(targetUserIdRaw) ? req.currentUser.id : targetUserIdRaw;

  // Set targetUserId on request for use in the route handler
  req.targetUserId = targetUserId;

  // Fetch target user if different from current user
  if (targetUserId !== req.currentUser.id) {
    const targetUser = await getUserById(targetUserId);
    req.targetUser = targetUser;

    // Check if users are linked
    try {
      const { rows } = await pool.query(
        `SELECT 1 FROM account_links
          WHERE status = 'accepted'
            AND ((requester_id = $1 AND target_id = $2) OR (requester_id = $2 AND target_id = $1))
          LIMIT 1`,
        [req.currentUser.id, targetUserId]
      );
      if (rows.length === 0) {
        return res.status(403).json({ ok: false, error: 'Not authorized' });
      }
    } catch (err) {
      console.error('Link authorization check failed:', err);
      return res.status(500).json({ ok: false, error: 'Authorization check failed' });
    }
  } else {
    req.targetUser = req.currentUser;
  }

  next();
};

module.exports = {
  requireLinkAuth
};