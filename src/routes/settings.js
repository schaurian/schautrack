const express = require('express');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const argon2 = require('argon2');
const { pool } = require('../db/pool');
const { requireLogin } = require('../middleware/auth');
const { csrfProtection } = require('../middleware/csrf');
const { encryptApiKey } = require('../lib/ai');
const { toInt } = require('../lib/utils');
const { MACRO_KEYS, parseMacroInput } = require('../lib/macros');
const { getLinkRequests, getAcceptedLinkUsers } = require('../lib/links');
const { broadcastSettingsChange } = require('./sse');

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
  const importFeedback = req.session.importFeedback || null;
  delete req.session.importFeedback;

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
    importFeedback,
  });
};

router.get('/settings', requireLogin, renderSettings);

router.post('/settings/preferences', requireLogin, csrfProtection, async (req, res) => {
  const wantsJson = (req.headers.accept || '').includes('application/json');
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
    if (wantsJson) return res.json({ ok: true });
  } catch (err) {
    console.error('Failed to update preferences', err);
    if (wantsJson) return res.status(500).json({ ok: false, error: 'Failed to save preferences' });
  }

  res.redirect('/settings');
});

router.post('/settings/macros', requireLogin, csrfProtection, async (req, res) => {
  const wantsJson = (req.headers.accept || '').includes('application/json');

  // Parse calorie goal (now stored in macro_goals.calories)
  const calorieGoal = parseMacroInput(req.body.calorie_goal);

  // Parse enabled macros, goals, and modes
  const enabledMacros = {};
  const macroGoals = {};

  // Calories enabled state
  enabledMacros.calories = req.body.calories_enabled === 'on' || req.body.calories_enabled === 'true';

  // Calorie goal and mode (stored in macro_goals alongside other macros)
  if (calorieGoal !== null) {
    macroGoals.calories = calorieGoal;
  }
  const calMode = req.body.calories_mode;
  if (calMode === 'limit' || calMode === 'target') {
    macroGoals.calories_mode = calMode;
  }

  for (const key of MACRO_KEYS) {
    enabledMacros[key] = req.body[`${key}_enabled`] === 'on' || req.body[`${key}_enabled`] === 'true';
    // Always store goals regardless of enabled state so they survive disable/re-enable
    const goal = parseMacroInput(req.body[`${key}_goal`]);
    if (goal !== null) {
      macroGoals[key] = goal;
    }
    const mode = req.body[`${key}_mode`];
    if (mode === 'limit' || mode === 'target') {
      macroGoals[`${key}_mode`] = mode;
    }
  }

  // Auto-calculate calories toggle (only valid when calories + protein + carbs + fat are all enabled)
  const wantsAutoCalc = req.body.auto_calc_calories === 'on' || req.body.auto_calc_calories === 'true';
  const canAutoCalc = enabledMacros.calories !== false
    && enabledMacros.protein === true
    && enabledMacros.carbs === true
    && enabledMacros.fat === true;
  enabledMacros.auto_calc_calories = wantsAutoCalc && canAutoCalc;

  // Parse goal threshold (0-99)
  const rawThreshold = parseMacroInput(req.body.goal_threshold);
  const goalThreshold = rawThreshold != null ? Math.min(Math.max(rawThreshold, 0), 99) : 10;

  try {
    await pool.query(
      'UPDATE users SET macros_enabled = $1, macro_goals = $2, goal_threshold = $3 WHERE id = $4',
      [JSON.stringify(enabledMacros), JSON.stringify(macroGoals), goalThreshold, req.currentUser.id]
    );

    // Derive the enabled macro keys list (excluding meta flags)
    const enabledKeys = MACRO_KEYS.filter((k) => enabledMacros[k]);
    const macroModes = {};
    for (const key of ['calories', ...MACRO_KEYS]) {
      if (macroGoals[`${key}_mode`]) macroModes[key] = macroGoals[`${key}_mode`];
    }

    broadcastSettingsChange(req.currentUser.id, {
      enabledMacros: enabledKeys,
      caloriesEnabled: enabledMacros.calories !== false,
      autoCalcCalories: enabledMacros.auto_calc_calories || false,
      macroGoals,
      macroModes,
      goalThreshold,
      dailyGoal: macroGoals.calories || null,
    });

    if (wantsJson) {
      return res.json({ ok: true });
    }
  } catch (err) {
    console.error('Failed to save macro preferences', err);
    if (wantsJson) {
      return res.status(500).json({ ok: false, error: 'Failed to save preferences' });
    }
  }

  res.redirect('/settings');
});

router.post('/settings/ai', requireLogin, csrfProtection, async (req, res) => {
  const { ai_key, ai_provider, ai_model, ai_daily_limit, clear_settings } = req.body;

  if (clear_settings === 'true') {
    try {
      await pool.query('UPDATE users SET ai_key = NULL, ai_endpoint = NULL, ai_model = NULL, ai_daily_limit = NULL, preferred_ai_provider = NULL WHERE id = $1', [req.currentUser.id]);
      req.session.aiFeedback = { type: 'success', message: 'AI settings cleared.' };
    } catch (err) {
      console.error('Failed to clear AI settings', err);
      req.session.aiFeedback = { type: 'error', message: 'Could not clear settings.' };
    }
    return res.redirect('/settings#ai-form');
  }

  const updates = [];
  const values = [];
  let idx = 1;

  // AI provider (user-scoped)
  const validProviders = ['openai', 'claude', 'ollama'];
  const newProvider = ai_provider && validProviders.includes(ai_provider) ? ai_provider : null;
  const providerChanged = newProvider !== (req.currentUser.preferred_ai_provider || null);
  updates.push(`preferred_ai_provider = $${idx}`);
  values.push(newProvider);
  idx++;

  // API key (user-scoped) — clear when provider changes and no new key given
  if (ai_key && ai_key.trim()) {
    const encrypted = encryptApiKey(ai_key.trim());
    if (encrypted) {
      updates.push(`ai_key = $${idx}`);
      values.push(encrypted);
      idx++;
    }
  } else if (providerChanged) {
    updates.push(`ai_key = NULL`);
  }

  // Model (user-scoped, sanitize)
  const modelVal = (ai_model || '').trim().slice(0, 100);
  updates.push(`ai_model = $${idx}`);
  values.push(modelVal || null);
  idx++;

  // Daily limit (user-scoped)
  const limitVal = parseInt(ai_daily_limit, 10);
  updates.push(`ai_daily_limit = $${idx}`);
  values.push(!Number.isNaN(limitVal) && limitVal > 0 ? limitVal : null);
  idx++;

  // Endpoint is admin-only (global setting) — never accept user override
  updates.push(`ai_endpoint = NULL`);

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

  res.redirect('/settings#ai-form');
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

    if (req.currentUser.totp_enabled) {
      const totpCode = req.body.totp_code || '';
      if (!totpCode) {
        req.session.passwordFeedback = { type: 'error', message: 'Please enter your 2FA code.' };
        return res.redirect('/settings');
      }
      const totpOk = speakeasy.totp.verify({
        secret: req.currentUser.totp_secret,
        encoding: 'base32',
        token: totpCode,
        window: 1,
      });
      if (!totpOk) {
        req.session.passwordFeedback = { type: 'error', message: 'Invalid 2FA code.' };
        return res.redirect('/settings');
      }
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

router.post('/2fa/setup', requireLogin, csrfProtection, async (req, res) => {
  const user = req.currentUser;
  const secret = speakeasy.generateSecret({
    name: `Schautrack (${user.email})`,
  });

  req.session.tempSecret = secret.base32;
  req.session.tempUrl = secret.otpauth_url;
  req.session.tempSecretCreatedAt = Date.now();
  res.redirect('/settings');
});

router.post('/2fa/cancel', requireLogin, csrfProtection, (req, res) => {
  delete req.session.tempSecret;
  delete req.session.tempUrl;
  delete req.session.tempSecretCreatedAt;
  res.redirect('/settings');
});

router.post('/2fa/enable', requireLogin, csrfProtection, async (req, res) => {
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

router.post('/2fa/disable', requireLogin, csrfProtection, async (req, res) => {
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
