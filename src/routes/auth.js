const express = require('express');
const rateLimit = require('express-rate-limit');
const argon2 = require('argon2');
const speakeasy = require('speakeasy');
const { pool } = require('../db/pool');
const { requireLogin } = require('../middleware/auth');
const { csrfProtection } = require('../middleware/csrf');
const { generateCaptcha, verifyCaptcha } = require('../lib/captcha');
const { 
  isSmtpConfigured, 
  generateResetCode, 
  sendVerificationEmail, 
  sendEmailChangeVerification, 
  sendEmail 
} = require('../lib/email');
const { getClientTimezone } = require('../lib/utils');

const router = express.Router();

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // max 10 attempts per windowMs
  message: { error: 'Too many attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
});

const strictLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // max 5 attempts per windowMs
  message: { error: 'Too many attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false },
});

// Helper functions for tokens
async function createPasswordResetToken(userId) {
  const code = generateResetCode();
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
  await pool.query(
    'DELETE FROM password_reset_tokens WHERE user_id = $1 AND used = FALSE',
    [userId]
  );
  await pool.query(
    'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
    [userId, code, expiresAt]
  );
  return code;
}

async function verifyPasswordResetToken(email, token) {
  const { rows } = await pool.query(
    `SELECT prt.id, prt.user_id, prt.expires_at, u.email
     FROM password_reset_tokens prt
     JOIN users u ON u.id = prt.user_id
     WHERE u.email = $1 AND prt.token = $2 AND prt.used = FALSE
     ORDER BY prt.created_at DESC
     LIMIT 1`,
    [email.toLowerCase().trim(), token]
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  if (new Date(row.expires_at) < new Date()) return null;
  return { tokenId: row.id, userId: row.user_id };
}

async function markTokenUsed(tokenId) {
  await pool.query('UPDATE password_reset_tokens SET used = TRUE WHERE id = $1', [tokenId]);
}

async function cleanExpiredTokens() {
  await pool.query('DELETE FROM password_reset_tokens WHERE expires_at < NOW() OR used = TRUE');
  await pool.query('DELETE FROM email_verification_tokens WHERE expires_at < NOW() OR used = TRUE');
}

// Email verification helpers
async function createEmailVerificationToken(userId) {
  const code = generateResetCode();
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
  await pool.query(
    'INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)',
    [userId, code, expiresAt]
  );
  return code;
}

async function verifyEmailToken(email, token) {
  const { rows } = await pool.query(
    `SELECT evt.id, evt.user_id, evt.expires_at, u.email
     FROM email_verification_tokens evt
     JOIN users u ON u.id = evt.user_id
     WHERE u.email = $1 AND evt.token = $2 AND evt.used = FALSE
     ORDER BY evt.created_at DESC
     LIMIT 1`,
    [email.toLowerCase().trim(), token]
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  if (new Date(row.expires_at) < new Date()) return null;
  return { tokenId: row.id, userId: row.user_id };
}

async function markEmailVerificationUsed(tokenId) {
  await pool.query('UPDATE email_verification_tokens SET used = TRUE WHERE id = $1', [tokenId]);
}

async function markUserVerified(userId) {
  await pool.query('UPDATE users SET email_verified = TRUE WHERE id = $1', [userId]);
}

async function createEmailChangeToken(userId, newEmail) {
  const code = generateResetCode();
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
  await pool.query(
    'INSERT INTO email_verification_tokens (user_id, token, expires_at, new_email) VALUES ($1, $2, $3, $4)',
    [userId, code, expiresAt, newEmail.toLowerCase().trim()]
  );
  return code;
}

async function verifyEmailChangeToken(userId, token) {
  const { rows } = await pool.query(
    `SELECT id, new_email, expires_at
     FROM email_verification_tokens
     WHERE user_id = $1 AND token = $2 AND used = FALSE AND new_email IS NOT NULL
     ORDER BY created_at DESC
     LIMIT 1`,
    [userId, token]
  );
  if (rows.length === 0) return null;
  const row = rows[0];
  if (new Date(row.expires_at) < new Date()) return null;
  return { tokenId: row.id, newEmail: row.new_email };
}

// Routes
router.get('/register', (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }
  // Clear any pending registration
  delete req.session.pendingRegistration;
  res.render('register', { error: null, email: '', requireCaptcha: false, captchaSvg: null });
});

router.post('/register', authLimiter, csrfProtection, async (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }

  const { step, captcha } = req.body;

  // Step 1: Credentials submitted - validate and show CAPTCHA
  if (step === 'credentials') {
    const email = (req.body.email || '').toLowerCase().trim();
    const { password, timezone } = req.body;

    if (!email || !password) {
      return res.render('register', {
        error: 'Email and password are required.',
        email,
        requireCaptcha: false,
        captchaSvg: null,
      });
    }

    if (password.length < 10) {
      return res.render('register', {
        error: 'Password must be at least 10 characters.',
        email,
        requireCaptcha: false,
        captchaSvg: null,
      });
    }

    try {
      const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
      if (existing.rows.length > 0) {
        return res.render('register', {
          error: 'Account already exists.',
          email,
          requireCaptcha: false,
          captchaSvg: null,
        });
      }

      // Store credentials in session and show CAPTCHA (hash password for security)
      const detectedTz = timezone || getClientTimezone(req) || 'UTC';
      const passwordHash = await argon2.hash(password);
      req.session.pendingRegistration = { email, passwordHash, timezone: detectedTz };

      const newCaptcha = generateCaptcha();
      req.session.captchaAnswer = newCaptcha.text;

      return res.render('register', {
        error: null,
        email,
        requireCaptcha: true,
        captchaSvg: newCaptcha.data,
      });
    } catch (err) {
      console.error('Registration error', err);
      return res.render('register', {
        error: 'Could not register user.',
        email,
        requireCaptcha: false,
        captchaSvg: null,
      });
    }
  }

  // Step 2: CAPTCHA submitted - verify and create account
  if (step === 'captcha') {
    const pending = req.session.pendingRegistration;
    if (!pending || !pending.email || !pending.passwordHash) {
      return res.render('register', {
        error: 'Registration session expired. Please start again.',
        email: '',
        requireCaptcha: false,
        captchaSvg: null,
      });
    }

    // Helper to render CAPTCHA step with error
    const renderCaptchaError = (error) => {
      const newCaptcha = generateCaptcha();
      req.session.captchaAnswer = newCaptcha.text;
      return res.render('register', {
        error,
        email: pending.email,
        requireCaptcha: true,
        captchaSvg: newCaptcha.data,
      });
    };

    if (!verifyCaptcha(req.session.captchaAnswer, captcha)) {
      return renderCaptchaError('Invalid captcha. Please try again.');
    }

    // Clear CAPTCHA after successful verification
    delete req.session.captchaAnswer;

    try {
      // Check again that email doesn't exist (race condition protection)
      const existing = await pool.query('SELECT id FROM users WHERE email = $1', [pending.email]);
      if (existing.rows.length > 0) {
        delete req.session.pendingRegistration;
        return res.render('register', {
          error: 'Account already exists.',
          email: pending.email,
          requireCaptcha: false,
          captchaSvg: null,
        });
      }

      // If SMTP is configured, require email verification
      if (isSmtpConfigured()) {
        const { rows } = await pool.query(
          'INSERT INTO users (email, password_hash, timezone, email_verified) VALUES ($1, $2, $3, FALSE) RETURNING id',
          [pending.email, pending.passwordHash, pending.timezone]
        );
        const userId = rows[0].id;
        const code = await createEmailVerificationToken(userId);
        await sendVerificationEmail(pending.email, code);

        // Clear pending and store email for verification page
        delete req.session.pendingRegistration;
        req.session.verifyEmail = pending.email;
        req.session.verifyCodeVerified = false;
        return res.redirect('/verify-email');
      } else {
        // No SMTP, auto-verify and log in
        const { rows } = await pool.query(
          'INSERT INTO users (email, password_hash, timezone, email_verified) VALUES ($1, $2, $3, TRUE) RETURNING id',
          [pending.email, pending.passwordHash, pending.timezone]
        );
        delete req.session.pendingRegistration;
        req.session.userId = rows[0].id;
        return res.redirect('/dashboard');
      }
    } catch (err) {
      console.error('Registration error', err);
      return renderCaptchaError('Could not register user.');
    }
  }

  // Invalid step
  res.redirect('/register');
});

router.get('/login', (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }
  // Show CAPTCHA if there have been 3+ failed attempts
  const failedAttempts = req.session.loginFailedAttempts || 0;
  let captchaSvg = null;
  if (failedAttempts >= 3) {
    const captcha = generateCaptcha();
    req.session.captchaAnswer = captcha.text;
    captchaSvg = captcha.data;
  }
  res.render('login', { error: null, requireToken: false, email: '', captchaSvg });
});

router.post('/login', authLimiter, csrfProtection, async (req, res) => {
  const { email, password, token, captcha } = req.body;
  const pendingUserId = req.session.pendingUserId;
  const failedAttempts = req.session.loginFailedAttempts || 0;

  // Helper to render login with CAPTCHA if needed
  const renderLogin = (error, opts = {}) => {
    const attempts = req.session.loginFailedAttempts || 0;
    let captchaSvg = null;
    if (attempts >= 3) {
      const newCaptcha = generateCaptcha();
      req.session.captchaAnswer = newCaptcha.text;
      captchaSvg = newCaptcha.data;
    }
    return res.render('login', {
      error,
      requireToken: opts.requireToken || false,
      email: opts.email || '',
      captchaSvg,
    });
  };

  // Helper to record a failed attempt
  const recordFailure = () => {
    req.session.loginFailedAttempts = (req.session.loginFailedAttempts || 0) + 1;
  };

  try {
    // Second step: pending login waiting for TOTP only
    if (token && pendingUserId) {
      const { getUserById } = require('../middleware/auth');
      const pendingUser = await getUserById(pendingUserId);
      if (!pendingUser || !pendingUser.totp_enabled || !pendingUser.totp_secret) {
        delete req.session.pendingUserId;
        return renderLogin('Invalid 2FA session.');
      }

      const ok = speakeasy.totp.verify({
        secret: pendingUser.totp_secret,
        encoding: 'base32',
        token,
        window: 1,
      });

      if (!ok) {
        return res.render('login', { error: 'Invalid 2FA code.', requireToken: true, email: pendingUser.email, captchaSvg: null });
      }

      // Success - clear failed attempts
      req.session.loginFailedAttempts = 0;
      req.session.userId = pendingUser.id;
      delete req.session.pendingUserId;
      return res.redirect('/dashboard');
    }

    if (!email || !password) {
      return renderLogin('Email and password are required.', { email: email || '' });
    }

    // Verify CAPTCHA if required (3+ failed attempts)
    if (failedAttempts >= 3) {
      if (!verifyCaptcha(req.session.captchaAnswer, captcha)) {
        return renderLogin('Invalid captcha. Please try again.', { email });
      }
      // Clear CAPTCHA after successful verification
      delete req.session.captchaAnswer;
    }

    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];
    if (!user) {
      recordFailure();
      return renderLogin('Invalid credentials.', { email });
    }

    const validPassword = await argon2.verify(user.password_hash, password);
    if (!validPassword) {
      recordFailure();
      return renderLogin('Invalid credentials.', { email });
    }

    // Check if email is verified (only if SMTP is configured)
    if (isSmtpConfigured() && !user.email_verified) {
      // Store email in session for verification page
      req.session.verifyEmail = user.email;
      req.session.verifyCodeVerified = false;
      return res.redirect('/verify-email');
    }

    if (user.totp_enabled) {
      // Require TOTP as a second step without re-entering password
      req.session.pendingUserId = user.id;
      return res.render('login', {
        error: null,
        requireToken: true,
        email,
        captchaSvg: null,
      });
    }

    // Success - clear failed attempts
    req.session.loginFailedAttempts = 0;
    req.session.userId = user.id;
    return res.redirect('/dashboard');
  } catch (err) {
    console.error('Login error', err);
    renderLogin('Could not log in.', { email: email || '' });
  }
});

router.post('/logout', requireLogin, (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

router.get('/forgot-password', (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }
  // Generate SVG CAPTCHA
  const captcha = generateCaptcha();
  req.session.captchaAnswer = captcha.text;
  res.render('forgot-password', {
    error: null,
    success: null,
    smtpConfigured: isSmtpConfigured(),
    captchaSvg: captcha.data,
    email: '',
  });
});

router.post('/forgot-password', strictLimiter, csrfProtection, async (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }

  const email = (req.body.email || '').toLowerCase().trim();

  // Helper to render with new CAPTCHA (preserves email)
  const renderWithCaptcha = (error) => {
    const captcha = generateCaptcha();
    req.session.captchaAnswer = captcha.text;
    return res.render('forgot-password', {
      error,
      success: null,
      smtpConfigured: isSmtpConfigured(),
      captchaSvg: captcha.data,
      email,
    });
  };

  if (!isSmtpConfigured()) {
    return renderWithCaptcha('Password recovery is not available. Please contact support.');
  }

  // Verify CAPTCHA
  const captchaAnswer = (req.body.captcha || '').trim();
  if (!verifyCaptcha(req.session.captchaAnswer, captchaAnswer)) {
    return renderWithCaptcha('Incorrect answer. Please try again.');
  }

  if (!email) {
    return renderWithCaptcha('Please enter your email address.');
  }

  try {
    const { rows } = await pool.query('SELECT id, email FROM users WHERE email = $1', [email]);
    const user = rows[0];

    if (user) {
      const code = await createPasswordResetToken(user.id);
      const subject = 'Password Reset Code - Schautrack';
      const text = `Your password reset code is: ${code}\n\nThis code expires in 30 minutes.\n\nIf you did not request this, you can ignore this email.`;
      const html = `
        <p>Your password reset code is:</p>
        <h2 style="font-family: monospace; letter-spacing: 4px;">${code}</h2>
        <p>This code expires in 30 minutes.</p>
        <p>If you did not request this, you can ignore this email.</p>
      `;
      await sendEmail(user.email, subject, text, html);
    }

    // Clear CAPTCHA answer from session
    delete req.session.captchaAnswer;

    // Store email in session for reset-password page
    req.session.resetEmail = email;
    req.session.resetCodeVerified = false;

    // Redirect to reset-password page
    res.redirect('/reset-password');
  } catch (err) {
    console.error('Forgot password error', err);
    renderWithCaptcha('Could not process request. Please try again.');
  }
});

router.get('/reset-password', (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }
  const email = req.session.resetEmail || '';
  const codeVerified = req.session.resetCodeVerified || false;

  // If no email in session, redirect to forgot-password
  if (!email) {
    return res.redirect('/forgot-password');
  }

  res.render('reset-password', { error: null, success: null, email, codeVerified });
});

router.post('/reset-password', csrfProtection, async (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }

  const email = req.session.resetEmail || '';
  const code = (req.body.code || '').trim();
  const password = req.body.password || '';
  const confirmPassword = req.body.confirm_password || '';
  const codeVerified = req.session.resetCodeVerified || false;

  // If no email in session, redirect to forgot-password
  if (!email) {
    return res.redirect('/forgot-password');
  }

  // Step 1: Verify code
  if (!codeVerified) {
    if (!code) {
      return res.render('reset-password', {
        error: 'Please enter the reset code.',
        success: null,
        email,
        codeVerified: false,
      });
    }

    try {
      const tokenResult = await verifyPasswordResetToken(email, code);
      if (!tokenResult) {
        return res.render('reset-password', {
          error: 'Invalid or expired code. Please request a new one.',
          success: null,
          email,
          codeVerified: false,
        });
      }

      // Code is valid - store in session and show password form
      req.session.resetCodeVerified = true;
      req.session.resetTokenId = tokenResult.tokenId;
      req.session.resetUserId = tokenResult.userId;
      return res.render('reset-password', {
        error: null,
        success: null,
        email,
        codeVerified: true,
      });
    } catch (err) {
      console.error('Reset code verification error', err);
      return res.render('reset-password', {
        error: 'Could not verify code. Please try again.',
        success: null,
        email,
        codeVerified: false,
      });
    }
  }

  // Step 2: Set new password
  if (!password) {
    return res.render('reset-password', {
      error: 'Password is required.',
      success: null,
      email,
      codeVerified: true,
    });
  }

  if (password !== confirmPassword) {
    return res.render('reset-password', {
      error: 'Passwords do not match.',
      success: null,
      email,
      codeVerified: true,
    });
  }

  if (password.length < 10) {
    return res.render('reset-password', {
      error: 'Password must be at least 10 characters.',
      success: null,
      email,
      codeVerified: true,
    });
  }

  try {
    const userId = req.session.resetUserId;
    const tokenId = req.session.resetTokenId;

    if (!userId || !tokenId) {
      // Session expired, start over
      delete req.session.resetEmail;
      delete req.session.resetCodeVerified;
      delete req.session.resetTokenId;
      delete req.session.resetUserId;
      return res.redirect('/forgot-password');
    }

    const hash = await argon2.hash(password);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, userId]);
    await markTokenUsed(tokenId);
    await cleanExpiredTokens();

    // Clear session data
    delete req.session.resetEmail;
    delete req.session.resetCodeVerified;
    delete req.session.resetTokenId;
    delete req.session.resetUserId;

    res.render('reset-password', {
      error: null,
      success: 'Password updated successfully. You can now log in.',
      email: '',
      codeVerified: false,
    });
  } catch (err) {
    console.error('Reset password error', err);
    res.render('reset-password', {
      error: 'Could not reset password. Please try again.',
      success: null,
      email,
      codeVerified: true,
    });
  }
});

// Email verification routes
router.get('/verify-email', (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }
  const email = req.session.verifyEmail || '';
  const codeVerified = req.session.verifyCodeVerified || false;
  const supportEmail = res.locals.supportEmail || null;

  // If no email in session, redirect to login
  if (!email) {
    return res.redirect('/login');
  }

  res.render('verify-email', { error: null, success: null, email, codeVerified, supportEmail });
});

router.post('/verify-email', async (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }

  const email = req.session.verifyEmail || '';
  const code = (req.body.code || '').trim();
  const supportEmail = res.locals.supportEmail || null;

  // If no email in session, redirect to login
  if (!email) {
    return res.redirect('/login');
  }

  // Rate limit: max 5 verification attempts per session
  const verifyAttempts = req.session.verifyAttempts || 0;
  if (verifyAttempts >= 5) {
    return res.render('verify-email', {
      error: 'Too many attempts. Please request a new code.',
      success: null,
      email,
      codeVerified: false,
      supportEmail,
    });
  }

  if (!code) {
    return res.render('verify-email', {
      error: 'Please enter the verification code.',
      success: null,
      email,
      codeVerified: false,
      supportEmail,
    });
  }

  try {
    const tokenResult = await verifyEmailToken(email, code);
    if (!tokenResult) {
      req.session.verifyAttempts = verifyAttempts + 1;
      return res.render('verify-email', {
        error: 'Invalid or expired code. Please request a new one.',
        success: null,
        email,
        codeVerified: false,
        supportEmail,
      });
    }

    // Mark token as used and user as verified
    await markEmailVerificationUsed(tokenResult.tokenId);
    await markUserVerified(tokenResult.userId);
    await cleanExpiredTokens();

    // Clear session data and log user in
    delete req.session.verifyEmail;
    delete req.session.verifyCodeVerified;
    delete req.session.verifyAttempts;
    delete req.session.resendAttempts;
    req.session.userId = tokenResult.userId;

    return res.redirect('/dashboard');
  } catch (err) {
    console.error('Email verification error', err);
    res.render('verify-email', {
      error: 'Could not verify email. Please try again.',
      success: null,
      email,
      codeVerified: false,
      supportEmail,
    });
  }
});

router.post('/verify-email/resend', async (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }

  const email = req.session.verifyEmail || '';
  const supportEmail = res.locals.supportEmail || null;

  // If no email in session, redirect to login
  if (!email) {
    return res.redirect('/login');
  }

  // Rate limit: max 3 resend attempts per session
  const resendAttempts = req.session.resendAttempts || 0;
  if (resendAttempts >= 3) {
    return res.render('verify-email', {
      error: 'Too many resend requests. Please wait and try again later.',
      success: null,
      email,
      codeVerified: false,
      supportEmail,
    });
  }

  try {
    // Get the user
    const { rows } = await pool.query('SELECT id, email_verified FROM users WHERE email = $1', [email]);
    const user = rows[0];

    if (!user) {
      delete req.session.verifyEmail;
      return res.redirect('/login');
    }

    if (user.email_verified) {
      delete req.session.verifyEmail;
      return res.render('verify-email', {
        error: null,
        success: 'Your email is already verified. You can log in.',
        email: '',
        codeVerified: true,
        supportEmail,
      });
    }

    // Create new token and send email
    const code = await createEmailVerificationToken(user.id);
    await sendVerificationEmail(email, code);

    // Increment resend counter and reset verify attempts
    req.session.resendAttempts = resendAttempts + 1;
    req.session.verifyAttempts = 0;

    res.render('verify-email', {
      error: null,
      success: 'A new verification code has been sent to your email.',
      email,
      codeVerified: false,
      supportEmail,
    });
  } catch (err) {
    console.error('Resend verification error', err);
    res.render('verify-email', {
      error: 'Could not send verification code. Please try again later.',
      success: null,
      email,
      codeVerified: false,
      supportEmail,
    });
  }
});

// Account deletion
router.post('/delete', requireLogin, async (req, res) => {
  const { password, token } = req.body;
  const { toInt } = require('../lib/utils');
  const userId = toInt(req.currentUser?.id);
  if (userId === null) {
    req.session.deleteFeedback = { type: 'error', message: 'Session invalid. Please log in again.' };
    return res.redirect('/login?next=/delete');
  }

  try {
    const { rows } = await pool.query(
      'SELECT id, email, password_hash, totp_enabled, totp_secret FROM users WHERE id = $1 LIMIT 1',
      [userId]
    );
    const user = rows[0];
    if (!user) {
      req.session.deleteFeedback = { type: 'error', message: 'Account not found. Please log in again.' };
      return res.redirect('/login?next=/delete');
    }

    const validPassword = await argon2.verify(user.password_hash || '', password || '');
    if (!validPassword) {
      req.session.deleteFeedback = { type: 'error', message: 'Incorrect password.' };
      return res.redirect('/delete');
    }

    if (user.totp_enabled) {
      if (!token) {
        req.session.deleteFeedback = { type: 'error', message: 'Enter your 2FA code to confirm deletion.' };
        return res.redirect('/delete');
      }
      const totpOk = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token,
        window: 1,
      });
      if (!totpOk) {
        req.session.deleteFeedback = { type: 'error', message: 'Invalid 2FA code.' };
        return res.redirect('/delete');
      }
    }

    await pool.query('BEGIN');
    
    // Delete all user data from all tables
    await pool.query('DELETE FROM calorie_entries WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM weight_entries WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM ai_usage WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM account_links WHERE requester_id = $1 OR target_id = $1', [userId]);
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM email_verification_tokens WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    
    await pool.query('COMMIT');

    return req.session.destroy(() => {
      res.render('delete', {
        activePage: null,
        deleteFeedback: { type: 'success', message: 'Your account and data were deleted. You have been signed out.' },
      });
    });
  } catch (err) {
    console.error('Account deletion failed', err);
    await pool.query('ROLLBACK').catch(() => {});
    req.session.deleteFeedback = { type: 'error', message: 'Could not delete account. Please try again.' };
    return res.redirect('/delete');
  }
});

// Email change routes
router.post('/settings/email/request', strictLimiter, requireLogin, async (req, res) => {
  const newEmail = (req.body.new_email || '').trim().toLowerCase();
  const password = req.body.password || '';
  const totpCode = req.body.totp_code || '';

  // Validate email format
  if (!newEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
    req.session.emailFeedback = { type: 'error', message: 'Please enter a valid email address.' };
    return res.redirect('/settings');
  }

  // Check if email is the same
  if (newEmail === req.currentUser.email.toLowerCase()) {
    req.session.emailFeedback = { type: 'error', message: 'New email is the same as your current email.' };
    return res.redirect('/settings');
  }

  // Check if email is already taken
  try {
    const { rows } = await pool.query('SELECT id FROM users WHERE LOWER(email) = $1', [newEmail]);
    if (rows.length > 0) {
      req.session.emailFeedback = { type: 'error', message: 'This email address is already in use.' };
      return res.redirect('/settings');
    }
  } catch (err) {
    console.error('Email check error', err);
    req.session.emailFeedback = { type: 'error', message: 'Could not verify email. Please try again.' };
    return res.redirect('/settings');
  }

  // Verify password
  try {
    const { rows } = await pool.query('SELECT password_hash, totp_enabled, totp_secret FROM users WHERE id = $1', [req.currentUser.id]);
    const user = rows[0];
    if (!user) {
      req.session.emailFeedback = { type: 'error', message: 'User not found.' };
      return res.redirect('/settings');
    }

    const validPassword = await argon2.verify(user.password_hash, password);
    if (!validPassword) {
      req.session.emailFeedback = { type: 'error', message: 'Incorrect password.' };
      return res.redirect('/settings');
    }

    // Verify TOTP if enabled
    if (user.totp_enabled) {
      if (!totpCode) {
        req.session.emailFeedback = { type: 'error', message: 'Please enter your 2FA code.' };
        return res.redirect('/settings');
      }
      const totpOk = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token: totpCode,
        window: 1,
      });
      if (!totpOk) {
        req.session.emailFeedback = { type: 'error', message: 'Invalid 2FA code.' };
        return res.redirect('/settings');
      }
    }

    // Create token and send verification email
    const code = await createEmailChangeToken(req.currentUser.id, newEmail);
    await sendEmailChangeVerification(newEmail, code);

    // Store pending email in session for the verification page
    req.session.pendingEmailChange = newEmail;
    req.session.emailChangeAttempts = 0;

    res.redirect('/settings/email/verify');
  } catch (err) {
    console.error('Email change request error', err);
    req.session.emailFeedback = { type: 'error', message: 'Could not process email change. Please try again.' };
    res.redirect('/settings');
  }
});

router.get('/settings/email/verify', requireLogin, (req, res) => {
  const pendingEmail = req.session.pendingEmailChange;
  if (!pendingEmail) {
    return res.redirect('/settings');
  }

  const feedback = req.session.emailVerifyFeedback || null;
  delete req.session.emailVerifyFeedback;

  res.render('verify-email-change', {
    user: req.currentUser,
    pendingEmail,
    feedback,
    activePage: 'settings',
  });
});

router.post('/settings/email/verify', requireLogin, async (req, res) => {
  const pendingEmail = req.session.pendingEmailChange;
  if (!pendingEmail) {
    return res.redirect('/settings');
  }

  const code = (req.body.code || '').trim();
  if (!code) {
    req.session.emailVerifyFeedback = { type: 'error', message: 'Please enter the verification code.' };
    return res.redirect('/settings/email/verify');
  }

  // Rate limit attempts
  req.session.emailChangeAttempts = (req.session.emailChangeAttempts || 0) + 1;
  if (req.session.emailChangeAttempts > 5) {
    delete req.session.pendingEmailChange;
    delete req.session.emailChangeAttempts;
    req.session.emailFeedback = { type: 'error', message: 'Too many failed attempts. Please start over.' };
    return res.redirect('/settings');
  }

  try {
    const result = await verifyEmailChangeToken(req.currentUser.id, code);
    if (!result) {
      req.session.emailVerifyFeedback = { type: 'error', message: 'Invalid or expired verification code.' };
      return res.redirect('/settings/email/verify');
    }

    // Update the user's email
    await pool.query('UPDATE users SET email = $1 WHERE id = $2', [result.newEmail, req.currentUser.id]);
    await markEmailVerificationUsed(result.tokenId);

    // Clear session state
    delete req.session.pendingEmailChange;
    delete req.session.emailChangeAttempts;

    req.session.emailFeedback = { type: 'success', message: 'Email address updated successfully.' };
    res.redirect('/settings');
  } catch (err) {
    console.error('Email change verification error', err);
    req.session.emailVerifyFeedback = { type: 'error', message: 'Could not verify code. Please try again.' };
    res.redirect('/settings/email/verify');
  }
});

router.post('/settings/email/cancel', requireLogin, (req, res) => {
  delete req.session.pendingEmailChange;
  delete req.session.emailChangeAttempts;
  res.redirect('/settings');
});

module.exports = router;