const express = require('express');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const argon2 = require('argon2');
const { pool } = require('../db/pool');
const { requireLogin } = require('../middleware/auth');
const { csrfProtection } = require('../middleware/csrf');
const { encryptApiKey } = require('../lib/ai');
const { toInt } = require('../lib/utils');
const { getLinkRequests, getAcceptedLinkUsers } = require('../lib/links');

const router = express.Router();

const renderSettings = async (req, res) => {
  const user = req.currentUser ? { ...req.currentUser, id: toInt(req.currentUser.id) } : null;

  // Check if temp secret has expired (10 minutes)
  const TOTP_SETUP_EXPIRY = 10 * 60 * 1000; // 10 minutes
  if (req.session.tempSecretCreatedAt && Date.now() - req.session.tempSecretCreatedAt > TOTP_SETUP_EXPIRY) {
    delete req.session.tempSecret;
    delete req.session.tempUrl;
    delete req.session.tempSecretCreatedAt;
  }

  const tempSecret = req.session.tempSecret;
  const tempUrl = req.session.tempUrl;
  const feedback = req.session.linkFeedback || null;
  delete req.session.linkFeedback;
  const passwordFeedback = req.session.passwordFeedback || null;
  delete req.session.passwordFeedback;
  const aiFeedback = req.session.aiFeedback || null;
  delete req.session.aiFeedback;
  const emailFeedback = req.session.emailFeedback || null;
  delete req.session.emailFeedback;

  let linkState = { incoming: [], outgoing: [] };
  let acceptedLinks = [];

  try {
    linkState = await getLinkRequests(user.id);
    acceptedLinks = await getAcceptedLinkUsers(user.id);
  } catch (err) {
    console.error('Failed to load link state', err);
  }

  let qrDataUrl = null;
  if (tempUrl) {
    try {
      qrDataUrl = await QRCode.toDataURL(tempUrl);
    } catch (err) {
      console.error('QR generation error', err);
    }
  }

  // Get all supported IANA timezones
  const timezones = Intl.supportedValuesOf('timeZone');

  // Prepare AI key info for display (masked)
  const { decryptApiKey } = require('../lib/ai');
  const hasAiKey = Boolean(user.ai_key);
  let aiKeyLast4 = '';

  if (hasAiKey) {
    const decrypted = decryptApiKey(user.ai_key);
    if (decrypted && decrypted.length >= 4) {
      aiKeyLast4 = decrypted.slice(-4);
    }
  }

  const MAX_LINKS = 3;

  res.render('settings', {
    user: {
      ...user,
      hasAiKey,
      aiKeyLast4,
    },
    hasTempSecret: Boolean(tempSecret),
    totpSecret: tempSecret || null,
    qrDataUrl,
    otpauthUrl: tempUrl || null,
    activePage: 'settings',
    incomingRequests: linkState.incoming,
    outgoingRequests: linkState.outgoing,
    acceptedLinks,
    linkFeedback: feedback,
    passwordFeedback,
    aiFeedback,
    emailFeedback,
    maxLinks: MAX_LINKS,
    availableSlots: Math.max(0, MAX_LINKS - acceptedLinks.length),
    timezones,
  });
};

router.get('/settings', requireLogin, renderSettings);

router.post('/settings/preferences', requireLogin, async (req, res) => {
  const unitRaw = (req.body.weight_unit || '').toLowerCase();
  const weightUnit = ['kg', 'lb'].includes(unitRaw) ? unitRaw : 'kg';

  // Validate timezone against supported IANA timezones
  const timezoneRaw = (req.body.timezone || '').trim();
  const supportedTimezones = Intl.supportedValuesOf('timeZone');
  const timezone = supportedTimezones.includes(timezoneRaw) ? timezoneRaw : null;

  try {
    if (timezone) {
      // Set timezone_manual flag to prevent auto-updates
      await pool.query('UPDATE users SET weight_unit = $1, timezone = $2, timezone_manual = TRUE WHERE id = $3', [weightUnit, timezone, req.currentUser.id]);
    } else {
      await pool.query('UPDATE users SET weight_unit = $1 WHERE id = $2', [weightUnit, req.currentUser.id]);
    }
  } catch (err) {
    console.error('Failed to update preferences', err);
  }

  res.redirect('/settings');
});

router.post('/settings/ai', requireLogin, async (req, res) => {
  const { ai_key, ai_endpoint, clear_settings } = req.body;

  if (clear_settings === 'true') {
    try {
      await pool.query('UPDATE users SET ai_key = NULL, ai_endpoint = NULL WHERE id = $1', [req.currentUser.id]);
      req.session.aiFeedback = { type: 'success', message: 'AI settings cleared.' };
    } catch (err) {
      console.error('Failed to clear AI settings', err);
      req.session.aiFeedback = { type: 'error', message: 'Could not clear settings.' };
    }
    return res.redirect('/settings');
  }

  const updates = [];
  const values = [];
  let idx = 1;

  // API key
  if (ai_key && ai_key.trim()) {
    const encrypted = encryptApiKey(ai_key.trim());
    if (encrypted) {
      updates.push(`ai_key = $${idx}`);
      values.push(encrypted);
      idx++;
    }
  }

  // Endpoint
  if (ai_endpoint !== undefined) {
    const trimmed = ai_endpoint.trim();

    // Basic URL validation
    if (trimmed && !trimmed.match(/^https?:\/\/.+/)) {
      req.session.aiFeedback = {
        type: 'error',
        message: 'Invalid endpoint URL. Must start with http:// or https://'
      };
      return res.redirect('/settings');
    }

    updates.push(`ai_endpoint = $${idx}`);
    values.push(trimmed || null);
    idx++;
  }

  try {
    if (updates.length > 0) {
      values.push(req.currentUser.id);
      await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${idx}`, values);
    }
    req.session.aiFeedback = { type: 'success', message: 'AI settings saved.' };
  } catch (err) {
    console.error('Failed to save AI settings', err);
    req.session.aiFeedback = { type: 'error', message: 'Could not save settings.' };
  }

  res.redirect('/settings');
});

router.post('/settings/password', requireLogin, csrfProtection, async (req, res) => {
  const currentPassword = req.body.current_password || '';
  const newPassword = req.body.new_password || '';
  const confirmPassword = req.body.confirm_password || '';

  if (!currentPassword || !newPassword) {
    req.session.passwordFeedback = { type: 'error', message: 'Current and new password are required.' };
    return res.redirect('/settings');
  }

  if (newPassword !== confirmPassword) {
    req.session.passwordFeedback = { type: 'error', message: 'New passwords do not match.' };
    return res.redirect('/settings');
  }

  if (newPassword.length < 10) {
    req.session.passwordFeedback = { type: 'error', message: 'New password must be at least 10 characters.' };
    return res.redirect('/settings');
  }

  try {
    const { rows } = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.currentUser.id]);
    const user = rows[0];
    if (!user) {
      req.session.passwordFeedback = { type: 'error', message: 'User not found.' };
      return res.redirect('/settings');
    }

    const validPassword = await argon2.verify(user.password_hash, currentPassword);
    if (!validPassword) {
      req.session.passwordFeedback = { type: 'error', message: 'Current password is incorrect.' };
      return res.redirect('/settings');
    }

    const hash = await argon2.hash(newPassword);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.currentUser.id]);

    req.session.passwordFeedback = { type: 'success', message: 'Password updated successfully.' };
    res.redirect('/settings');
  } catch (err) {
    console.error('Password change error', err);
    req.session.passwordFeedback = { type: 'error', message: 'Could not change password. Please try again.' };
    res.redirect('/settings');
  }
});

// 2FA routes
router.get('/2fa', requireLogin, (req, res) => res.redirect('/settings'));

router.get('/2fa/setup', requireLogin, async (req, res) => {
  const user = req.currentUser;
  const secret = speakeasy.generateSecret({
    name: `Schautrack (${user.email})`,
  });

  req.session.tempSecret = secret.base32;
  req.session.tempUrl = secret.otpauth_url;
  req.session.tempSecretCreatedAt = Date.now();
  res.redirect('/settings');
});

router.get('/2fa/cancel', requireLogin, (req, res) => {
  delete req.session.tempSecret;
  delete req.session.tempUrl;
  delete req.session.tempSecretCreatedAt;
  res.redirect('/settings');
});

router.post('/2fa/enable', requireLogin, async (req, res) => {
  const { token } = req.body;
  const secret = req.session.tempSecret;

  if (!secret) {
    return res.redirect('/settings');
  }

  const ok = speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
    window: 1,
  });

  if (!ok) {
    return res.redirect('/settings');
  }

  try {
    await pool.query('UPDATE users SET totp_secret = $1, totp_enabled = TRUE WHERE id = $2', [
      secret,
      req.currentUser.id,
    ]);
    delete req.session.tempSecret;
    delete req.session.tempUrl;
    delete req.session.tempSecretCreatedAt;
  } catch (err) {
    console.error('Failed to enable 2FA', err);
  }

  res.redirect('/settings');
});

router.post('/2fa/disable', requireLogin, async (req, res) => {
  const { token } = req.body;
  const user = req.currentUser;

  if (!user.totp_enabled || !user.totp_secret) {
    return res.redirect('/settings');
  }

  const ok = speakeasy.totp.verify({
    secret: user.totp_secret,
    encoding: 'base32',
    token,
    window: 1,
  });

  if (!ok) {
    return res.redirect('/settings');
  }

  try {
    await pool.query('UPDATE users SET totp_secret = NULL, totp_enabled = FALSE WHERE id = $1', [user.id]);
  } catch (err) {
    console.error('Failed to disable 2FA', err);
  }

  res.redirect('/settings');
});

module.exports = router;