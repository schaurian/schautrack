const express = require('express');
const { pool, getEffectiveSetting, setAdminSetting } = require('../db/pool');
const { requireLogin, requireAdmin } = require('../middleware/auth');

const router = express.Router();

router.get('/admin', requireLogin, requireAdmin, async (req, res) => {
  const { rows: users } = await pool.query(
    'SELECT id, email, created_at, email_verified FROM users ORDER BY created_at DESC'
  );

  const settings = {
    support_email: await getEffectiveSetting('support_email', process.env.SUPPORT_EMAIL),
    imprint_address: await getEffectiveSetting('imprint_address', process.env.IMPRINT_ADDRESS),
    imprint_email: await getEffectiveSetting('imprint_email', process.env.IMPRINT_EMAIL),
    enable_legal: await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL),
    ai_provider: await getEffectiveSetting('ai_provider', process.env.AI_PROVIDER),
    ai_key: await getEffectiveSetting('ai_key', process.env.AI_KEY),
    ai_endpoint: await getEffectiveSetting('ai_endpoint', process.env.AI_ENDPOINT),
    ai_model: await getEffectiveSetting('ai_model', process.env.AI_MODEL),
    ai_daily_limit: await getEffectiveSetting('ai_daily_limit', process.env.AI_DAILY_LIMIT),
  };

  const feedback = req.session.adminFeedback || null;
  delete req.session.adminFeedback;

  res.render('admin', {
    user: req.currentUser,
    activePage: 'admin',
    users,
    settings,
    feedback,
  });
});

router.post('/admin/settings', requireLogin, requireAdmin, async (req, res) => {
  const { key, value } = req.body;

  const allowedKeys = {
    support_email: 'SUPPORT_EMAIL',
    imprint_address: 'IMPRINT_ADDRESS',
    imprint_email: 'IMPRINT_EMAIL',
    enable_legal: 'ENABLE_LEGAL',
    ai_provider: 'AI_PROVIDER',
    ai_key: 'AI_KEY',
    ai_endpoint: 'AI_ENDPOINT',
    ai_model: 'AI_MODEL',
    ai_daily_limit: 'AI_DAILY_LIMIT',
  };

  if (!allowedKeys[key]) {
    req.session.adminFeedback = { type: 'error', message: 'Invalid setting key.' };
    return res.redirect('/admin');
  }

  const envValue = process.env[allowedKeys[key]];
  if (envValue !== undefined && envValue !== null && envValue !== '') {
    req.session.adminFeedback = { type: 'error', message: 'This setting is controlled by environment variable.' };
    return res.redirect('/admin');
  }

  try {
    await setAdminSetting(key, value);
    req.session.adminFeedback = { type: 'success', message: 'Setting updated.' };
  } catch (err) {
    console.error('Failed to update admin setting', err);
    req.session.adminFeedback = { type: 'error', message: 'Failed to update setting.' };
  }
  res.redirect('/admin');
});

router.post('/admin/users/:id/delete', requireLogin, requireAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);

  if (Number.isNaN(userId)) {
    req.session.adminFeedback = { type: 'error', message: 'Invalid user ID.' };
    return res.redirect('/admin');
  }

  if (userId === req.currentUser.id) {
    req.session.adminFeedback = { type: 'error', message: 'Cannot delete yourself.' };
    return res.redirect('/admin');
  }

  try {
    await pool.query('BEGIN');
    
    // Delete all user data from all tables (admin deletion)
    await pool.query('DELETE FROM calorie_entries WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM weight_entries WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM ai_usage WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM account_links WHERE requester_id = $1 OR target_id = $1', [userId]);
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM email_verification_tokens WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    
    await pool.query('COMMIT');
    req.session.adminFeedback = { type: 'success', message: 'User deleted completely.' };
  } catch (err) {
    await pool.query('ROLLBACK');
    console.error('Failed to delete user', err);
    req.session.adminFeedback = { type: 'error', message: 'Failed to delete user.' };
  }
  res.redirect('/admin');
});

module.exports = router;