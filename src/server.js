require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const app = express();
const PORT = process.env.PORT || 3000;
const sessionCookieSecure = process.env.COOKIE_SECURE === 'true';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://schautrack:schautrack@localhost:5432/schautrack',
});

function parseAmount(input) {
  if (input === undefined || input === null) {
    return { ok: false, value: 0 };
  }

  const expr = String(input)
    .replace(/\s+/g, '')
    .replace(/,/g, '')
    .replace(/[x×]/gi, '*')
    .replace(/÷/g, '/')
    .trim();

  if (!expr || expr.length > 120 || !/^[0-9+\-*/().]+$/.test(expr)) {
    return { ok: false, value: 0 };
  }

  try {
    const value = Function('"use strict"; return (' + expr + ')')();
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return { ok: false, value: 0 };
    }
    return { ok: true, value: Math.round(value) };
  } catch (err) {
    return { ok: false, value: 0 };
  }
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(express.urlencoded({ extended: false }));

app.use(
  session({
    store: new PgSession({
      pool,
      tableName: 'session',
    }),
    secret: process.env.SESSION_SECRET || 'dev-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7,
      secure: sessionCookieSecure,
      sameSite: 'lax',
    },
  })
);

app.use(async (req, res, next) => {
  if (!req.session.userId) {
    req.currentUser = null;
    res.locals.currentUser = null;
    return next();
  }

  try {
    const user = await getUserById(req.session.userId);
    req.currentUser = user || null;
    res.locals.currentUser = user || null;
  } catch (err) {
    console.error('Failed to load user from session', err);
  }
  next();
});

const requireAuth = (req, res, next) => {
  if (!req.currentUser) {
    return res.redirect('/login');
  }
  next();
};

const renderSettings = async (req, res) => {
  const user = req.currentUser;
  const tempSecret = req.session.tempSecret;
  const tempUrl = req.session.tempUrl;

  let qrDataUrl = null;
  if (tempUrl) {
    try {
      qrDataUrl = await QRCode.toDataURL(tempUrl);
    } catch (err) {
      console.error('QR generation error', err);
    }
  }

  res.render('settings', {
    user,
    hasTempSecret: Boolean(tempSecret),
    qrDataUrl,
    otpauthUrl: tempUrl || null,
    activePage: 'settings',
  });
};

async function getUserById(id) {
  const { rows } = await pool.query(
    'SELECT id, email, daily_goal, totp_enabled, totp_secret FROM users WHERE id = $1',
    [id]
  );
  return rows[0];
}

app.get('/', (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

app.get('/register', (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }
  res.render('register', { error: null });
});

app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.render('register', { error: 'Email and password are required.' });
  }

  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.render('register', { error: 'Account already exists.' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
      [email, passwordHash]
    );
    req.session.userId = rows[0].id;
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Registration error', err);
    res.render('register', { error: 'Could not register user.' });
  }
});

app.get('/login', (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }
  res.render('login', { error: null, requireToken: false, email: '' });
});

app.post('/login', async (req, res) => {
  const { email, password, token } = req.body;
  if (!email || !password) {
    return res.render('login', {
      error: 'Email and password are required.',
      requireToken: false,
      email: email || '',
    });
  }

  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];
    if (!user) {
      return res.render('login', { error: 'Invalid credentials.', requireToken: false, email });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.render('login', {
        error: 'Invalid credentials.',
        requireToken: user.totp_enabled,
        email,
      });
    }

    if (user.totp_enabled) {
      if (!token) {
        return res.render('login', {
          error: 'Enter your 2FA code.',
          requireToken: true,
          email,
        });
      }

      const ok = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token,
        window: 1,
      });

      if (!ok) {
        return res.render('login', { error: 'Invalid 2FA code.', requireToken: true, email });
      }
    }

    req.session.userId = user.id;
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Login error', err);
    res.render('login', { error: 'Could not log in.', requireToken: false, email: email || '' });
  }
});

app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/dashboard', requireAuth, async (req, res) => {
  const user = req.currentUser;
  const daysToShow = 14;
  const goalThreshold = user.daily_goal ? Math.round(user.daily_goal * 1.1) : null;

  const { rows } = await pool.query(
    'SELECT entry_date, SUM(amount) AS total FROM calorie_entries WHERE user_id = $1 GROUP BY entry_date ORDER BY entry_date DESC LIMIT $2',
    [user.id, daysToShow]
  );

  const totalsByDate = new Map();
  rows.forEach((row) => {
    const dateStr = row.entry_date.toISOString().slice(0, 10);
    totalsByDate.set(dateStr, parseInt(row.total, 10));
  });

  const today = new Date();
  const todayStr = today.toISOString().slice(0, 10);
  const dailyStats = [];
  for (let i = 1; i <= daysToShow; i += 1) {
    const current = new Date(today);
    current.setDate(today.getDate() - i);
    const dateStr = current.toISOString().slice(0, 10);
    const total = totalsByDate.get(dateStr) || 0;
    let status = 'none';
    let overThreshold = false;
    if (user.daily_goal) {
      if (total === 0) {
        status = 'zero';
      } else if (total <= user.daily_goal) {
        status = 'under';
      } else if (goalThreshold && total > goalThreshold) {
        status = 'over_threshold';
        overThreshold = true;
      } else {
        status = 'over';
      }
    }

    dailyStats.push({ date: dateStr, total, status, overThreshold });
  }

  const todayTotal = totalsByDate.get(todayStr) || 0;
  const goalStatus = !user.daily_goal ? 'unset' : todayTotal <= user.daily_goal ? 'under' : 'over';
  const goalDelta = user.daily_goal ? Math.abs(user.daily_goal - todayTotal) : null;

  res.render('dashboard', {
    user,
    todayTotal,
    goalStatus,
    goalDelta,
    dailyStats,
    activePage: 'dashboard',
  });
});

app.post('/goal', requireAuth, async (req, res) => {
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

app.post('/entries', requireAuth, async (req, res) => {
  const { value: amount, ok } = parseAmount(req.body.amount);
  const entryDate = req.body.entry_date || new Date().toISOString().slice(0, 10);

  if (!ok || amount === 0) {
    return res.redirect('/dashboard');
  }

  try {
    await pool.query(
      'INSERT INTO calorie_entries (user_id, entry_date, amount) VALUES ($1, $2, $3)',
      [req.currentUser.id, entryDate, amount]
    );
  } catch (err) {
    console.error('Failed to add entry', err);
  }

  res.redirect('/dashboard');
});

app.get('/2fa', requireAuth, (req, res) => res.redirect('/settings'));

app.get('/2fa/setup', requireAuth, async (req, res) => {
  const user = req.currentUser;
  const secret = speakeasy.generateSecret({
    name: `Schautrack (${user.email})`,
  });

  req.session.tempSecret = secret.base32;
  req.session.tempUrl = secret.otpauth_url;
  res.redirect('/settings');
});

app.post('/2fa/enable', requireAuth, async (req, res) => {
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
  } catch (err) {
    console.error('Failed to enable 2FA', err);
  }

  res.redirect('/settings');
});

app.post('/2fa/disable', requireAuth, async (req, res) => {
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

app.get('/settings', requireAuth, renderSettings);

app.listen(PORT, () => {
  console.log(`Schautrack listening on port ${PORT}`);
});
