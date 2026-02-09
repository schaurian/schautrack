const { pool } = require('../db/pool');
const { toInt } = require('../lib/utils');

async function getUserById(id) {
  const { rows } = await pool.query(
    'SELECT id, email, daily_goal, totp_enabled, totp_secret, timezone, weight_unit, timezone_manual, preferred_ai_provider, ai_key, ai_endpoint FROM users WHERE id = $1',
    [id]
  );
  const user = rows[0];
  if (!user) return null;
  return { ...user, id: toInt(user.id) };
}

// Admin email - user with this email gets admin access
const adminEmail = process.env.ADMIN_EMAIL || null;

const isAdmin = (user) => {
  return adminEmail && user && user.email.toLowerCase() === adminEmail.toLowerCase();
};

const attachUser = async (req, res, next) => {
  if (!req.session.userId) {
    req.currentUser = null;
    res.locals.currentUser = null;
    res.locals.isAdmin = false;
    return next();
  }

  try {
    const user = await getUserById(req.session.userId);
    req.currentUser = user || null;
    res.locals.currentUser = user || null;
    res.locals.isAdmin = adminEmail && user && user.email.toLowerCase() === adminEmail.toLowerCase();
  } catch (err) {
    console.error('Failed to load user from session', err);
    res.locals.isAdmin = false;
  }
  next();
};

const requireLogin = (req, res, next) => {
  if (!req.currentUser) {
    return res.redirect('/login');
  }
  next();
};

const requireAdmin = (req, res, next) => {
  if (!req.currentUser || !isAdmin(req.currentUser)) {
    return res.status(404).send('Not found');
  }
  next();
};

module.exports = {
  getUserById,
  isAdmin,
  attachUser,
  requireLogin,
  requireAdmin
};