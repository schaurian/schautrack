require('dotenv').config();
const path = require('path');
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;
const sessionCookieSecure = process.env.COOKIE_SECURE === 'true';
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
});
const MAX_LINKS = 3;
const MAX_HISTORY_DAYS = 180;
const DEFAULT_RANGE_DAYS = 14;
const entryEventClients = new Map(); // userId -> Set(res)
const supportEmail = process.env.SUPPORT_EMAIL || 'homebox-support@schauer.to';
const KG_TO_LB = 2.20462;

const parseCookies = (header) => {
  if (!header) return {};
  return header.split(';').reduce((acc, part) => {
    const [rawKey, ...rest] = part.split('=');
    const key = rawKey && rawKey.trim();
    if (!key) return acc;
    acc[key] = rest.join('=').trim();
    return acc;
  }, {});
};

const getClientTimezone = (req) => {
  const fromHeader = (req.headers['x-timezone'] || req.headers['x-tz'] || '').trim();
  if (fromHeader) return fromHeader.slice(0, 100);
  const cookies = parseCookies(req.headers.cookie);
  const fromCookie = (cookies.timezone || '').trim();
  if (fromCookie) return fromCookie.slice(0, 100);
  return null;
};

const rememberClientTimezone = (req, res) => {
  const tz = getClientTimezone(req);
  if (tz) {
    // Persist for future requests; express sets cookies without extra middleware.
    res.cookie('timezone', tz, { sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 365 });
  }
  return tz;
};

const toInt = (value) => {
  const num = parseInt(value, 10);
  return Number.isNaN(num) ? null : num;
};

const toIsoDate = (date) => date.toISOString().slice(0, 10);

const formatDateInTz = (date, timeZone) => {
  try {
    return new Intl.DateTimeFormat('en-CA', {
      timeZone: timeZone || 'UTC',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).format(date);
  } catch (err) {
    return toIsoDate(date);
  }
};

const formatTimeInTz = (date, timeZone) => {
  try {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: timeZone || 'UTC',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).format(date);
  } catch (err) {
    return date.toISOString().slice(11, 16);
  }
};

const kgToLbs = (kg) => (typeof kg === 'number' ? Math.round(kg * KG_TO_LB * 10) / 10 : null);
const lbsToKg = (lbs) => {
  const num = parseFloat(lbs);
  if (Number.isNaN(num) || num <= 0) return null;
  return Math.round((num / KG_TO_LB) * 100) / 100;
};

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://schautrack:schautrack@localhost:5432/schautrack',
});

async function ensureAccountLinksSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS account_links (
      id SERIAL PRIMARY KEY,
      requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      target_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status TEXT NOT NULL CHECK (status IN ('pending', 'accepted')),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      CONSTRAINT account_links_not_self CHECK (requester_id <> target_id)
    );
    ALTER TABLE account_links
      ADD COLUMN IF NOT EXISTS label TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS account_links_pair_idx
      ON account_links (LEAST(requester_id, target_id), GREATEST(requester_id, target_id));
    CREATE INDEX IF NOT EXISTS account_links_requester_idx ON account_links (requester_id);
    CREATE INDEX IF NOT EXISTS account_links_target_idx ON account_links (target_id);
    CREATE INDEX IF NOT EXISTS account_links_status_idx ON account_links (status);
  `);
}

async function ensureWeightEntriesSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS weight_entries (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      entry_date DATE NOT NULL,
      weight NUMERIC(6, 2) NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      CONSTRAINT weight_entries_positive CHECK (weight > 0)
    );

    CREATE UNIQUE INDEX IF NOT EXISTS weight_unique_per_day_idx ON weight_entries (user_id, entry_date);
  `);
}

async function ensureUserPrefsSchema() {
  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS timezone TEXT,
      ADD COLUMN IF NOT EXISTS weight_unit TEXT;
  `);
}

function parseAmount(input) {
  if (input === undefined || input === null) {
    return { ok: false, value: 0 };
  }

  const expr = String(input)
    .replace(/\s+/g, '')
    .replace(/,/g, '')
    .replace(/[–—−]/g, '-')
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

async function getAcceptedLinkUsers(userId) {
  const uid = toInt(userId);
  if (uid === null) return [];
  const { rows } = await pool.query(
    `SELECT al.id AS link_id,
            al.created_at,
            al.label,
            CASE WHEN al.requester_id = $1 THEN al.target_id ELSE al.requester_id END AS other_id,
            u.email AS other_email,
            u.daily_goal AS other_daily_goal
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
    since: row.created_at,
  }));
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

function setLinkFeedback(req, type, message) {
  req.session.linkFeedback = { type, message };
}

function addEntryEventClient(userId, res) {
  if (!entryEventClients.has(userId)) {
    entryEventClients.set(userId, new Set());
  }
  entryEventClients.get(userId).add(res);
}

function removeEntryEventClient(userId, res) {
  const set = entryEventClients.get(userId);
  if (!set) return;
  set.delete(res);
  if (set.size === 0) {
    entryEventClients.delete(userId);
  }
}

function sendEntryEvent(userId, payload) {
  const set = entryEventClients.get(userId);
  if (!set || set.size === 0) return;
  const data = `event: entry-change\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const res of set) {
    res.write(data);
  }
}

async function broadcastEntryChange(sourceUserId) {
  const uid = toInt(sourceUserId);
  if (uid === null) return;
  const targets = new Set([uid]);
  try {
    const links = await getAcceptedLinkUsers(uid);
    links.forEach((link) => targets.add(link.userId));
  } catch (err) {
    console.error('Failed to load linked users for broadcast', err);
  }
  const payload = { sourceUserId: uid, at: Date.now() };
  targets.forEach((targetId) => sendEntryEvent(targetId, payload));
}

function buildDayOptions(daysToShow) {
  const today = new Date();
  const startDate = new Date(today);
  startDate.setDate(today.getDate() - (daysToShow - 1));
  return buildDayOptionsBetween(startDate, today);
}

function buildDayOptionsBetween(startDate, endDate) {
  const dayOptions = [];
  const cursor = new Date(endDate);
  const minDate = new Date(startDate);
  for (let i = 0; i < MAX_HISTORY_DAYS; i += 1) {
    if (cursor < minDate) break;
    dayOptions.push(toIsoDate(cursor));
    cursor.setDate(cursor.getDate() - 1);
  }
  return dayOptions;
}

function getDateBounds(dayOptions) {
  return {
    newest: dayOptions[0],
    oldest: dayOptions[dayOptions.length - 1],
  };
}

function parseDateParam(value) {
  if (!value || typeof value !== 'string') return null;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value.trim())) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

function sanitizeDateRange(startStr, endStr, fallbackDays = DEFAULT_RANGE_DAYS) {
  const today = new Date();
  const requestedEnd = parseDateParam(endStr);
  let endDate = requestedEnd && requestedEnd <= today ? requestedEnd : today;

  const requestedStart = parseDateParam(startStr);
  const fallbackStart = new Date(endDate);
  fallbackStart.setDate(endDate.getDate() - (fallbackDays - 1));

  let startDate = requestedStart || fallbackStart;
  if (startDate > endDate) {
    startDate = new Date(endDate);
  }

  const maxLookback = new Date(endDate);
  maxLookback.setDate(endDate.getDate() - (MAX_HISTORY_DAYS - 1));
  if (startDate < maxLookback) {
    startDate = maxLookback;
  }

  return { startDate, endDate };
}

async function getTotalsByDate(userId, oldestDate, newestDate) {
  const { rows } = await pool.query(
    `SELECT entry_date, SUM(amount) AS total
       FROM calorie_entries
      WHERE user_id = $1
        AND entry_date BETWEEN $2 AND $3
      GROUP BY entry_date
      ORDER BY entry_date DESC`,
    [userId, oldestDate, newestDate]
  );

  const totalsByDate = new Map();
  rows.forEach((row) => {
    const dateStr = row.entry_date.toISOString().slice(0, 10);
    totalsByDate.set(dateStr, parseInt(row.total, 10));
  });
  return totalsByDate;
}

function buildDailyStats(dayOptions, totalsByDate, dailyGoal) {
  const goalThreshold = dailyGoal ? Math.round(dailyGoal * 1.1) : null;
  return dayOptions.map((dateStr) => {
    const total = totalsByDate.get(dateStr) || 0;
    let status = 'none';
    let overThreshold = false;
    if (dailyGoal) {
      if (total === 0) {
        status = 'zero';
      } else if (total <= dailyGoal) {
        status = 'under';
      } else if (goalThreshold && total > goalThreshold) {
        status = 'over_threshold';
        overThreshold = true;
      } else {
        status = 'over';
      }
    }
    return { date: dateStr, total, status, overThreshold };
  });
}

function parseWeight(input) {
  if (input === undefined || input === null) {
    return { ok: false, value: null };
  }
  const normalized = String(input)
    .replace(',', '.')
    .replace(/[^0-9.+-]/g, '')
    .trim();
  if (!normalized || normalized.length > 12) {
    return { ok: false, value: null };
  }
  const value = Number.parseFloat(normalized);
  if (!Number.isFinite(value) || value <= 0 || value > 1500) {
    return { ok: false, value: null };
  }
  return { ok: true, value: Math.round(value * 10) / 10 };
}

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

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use((req, res, next) => {
  res.locals.buildVersion = process.env.BUILD_VERSION || null;
  res.locals.supportEmail = supportEmail;
  next();
});

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

// Capture client timezone from cookie/header and persist for authenticated users.
app.use((req, res, next) => {
  const detectedTz = rememberClientTimezone(req, res);
  if (req.currentUser && detectedTz && req.currentUser.timezone !== detectedTz) {
    req.currentUser.timezone = detectedTz;
    res.locals.currentUser = req.currentUser;
    pool
      .query('UPDATE users SET timezone = $1 WHERE id = $2', [detectedTz, req.currentUser.id])
      .catch((err) => console.error('Failed to persist timezone', err));
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
  const user = req.currentUser ? { ...req.currentUser, id: toInt(req.currentUser.id) } : null;
  const tempSecret = req.session.tempSecret;
  const tempUrl = req.session.tempUrl;
  const feedback = req.session.linkFeedback || null;
  delete req.session.linkFeedback;

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

  res.render('settings', {
    user,
    hasTempSecret: Boolean(tempSecret),
    qrDataUrl,
    otpauthUrl: tempUrl || null,
    activePage: 'settings',
    incomingRequests: linkState.incoming,
    outgoingRequests: linkState.outgoing,
    acceptedLinks,
    linkFeedback: feedback,
    maxLinks: MAX_LINKS,
    availableSlots: Math.max(0, MAX_LINKS - acceptedLinks.length),
  });
};

async function getUserById(id) {
  const { rows } = await pool.query(
    'SELECT id, email, daily_goal, totp_enabled, totp_secret, timezone, weight_unit FROM users WHERE id = $1',
    [id]
  );
  const user = rows[0];
  if (!user) return null;
  return { ...user, id: toInt(user.id) };
}

app.get('/', (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

app.get('/privacy', (req, res) => {
  res.render('privacy', { activePage: null });
});

app.get('/delete', (req, res) => {
  const feedback = req.session.deleteFeedback || null;
  delete req.session.deleteFeedback;
  res.render('delete', { activePage: null, deleteFeedback: feedback });
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
  const pendingUserId = req.session.pendingUserId;

  try {
    // Second step: pending login waiting for TOTP only
    if (token && pendingUserId) {
      const pendingUser = await getUserById(pendingUserId);
      if (!pendingUser || !pendingUser.totp_enabled || !pendingUser.totp_secret) {
        delete req.session.pendingUserId;
        return res.render('login', { error: 'Invalid 2FA session.', requireToken: false, email: '' });
      }

      const ok = speakeasy.totp.verify({
        secret: pendingUser.totp_secret,
        encoding: 'base32',
        token,
        window: 1,
      });

      if (!ok) {
        return res.render('login', { error: 'Invalid 2FA code.', requireToken: true, email: pendingUser.email });
      }

      req.session.userId = pendingUser.id;
      delete req.session.pendingUserId;
      return res.redirect('/dashboard');
    }

    if (!email || !password) {
      return res.render('login', {
        error: 'Email and password are required.',
        requireToken: false,
        email: email || '',
      });
    }

    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];
    if (!user) {
      return res.render('login', { error: 'Invalid credentials.', requireToken: false, email });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.render('login', {
        error: 'Invalid credentials.',
        requireToken: false,
        email,
      });
    }

    if (user.totp_enabled) {
      // Require TOTP as a second step without re-entering password
      req.session.pendingUserId = user.id;
      return res.render('login', {
        error: null,
        requireToken: true,
        email,
      });
    }

    req.session.userId = user.id;
    return res.redirect('/dashboard');
  } catch (err) {
    console.error('Login error', err);
    res.render('login', { error: 'Could not log in.', requireToken: false, email: email || '' });
  }
});

app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.post('/delete', requireAuth, async (req, res) => {
  const { password, token } = req.body;
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

    const validPassword = await bcrypt.compare(password || '', user.password_hash || '');
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
    await pool.query('DELETE FROM calorie_entries WHERE user_id = $1', [userId]);
    await pool.query('DELETE FROM account_links WHERE requester_id = $1 OR target_id = $1', [userId]);
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

app.get('/dashboard', requireAuth, async (req, res) => {
  const user = { ...req.currentUser, id: toInt(req.currentUser.id) };
  const detectedTz = rememberClientTimezone(req, res);
  const userTimeZone = detectedTz || user.timezone || 'UTC';
  const serverNow = new Date();
  const todayStrTz = formatDateInTz(serverNow, userTimeZone);
  const requestedRange = parseInt(req.query.range, 10);
  const requestedDays = Number.isInteger(requestedRange)
    ? Math.min(Math.max(requestedRange, 7), MAX_HISTORY_DAYS)
    : DEFAULT_RANGE_DAYS;
  const { startDate, endDate } = sanitizeDateRange(req.query.start, req.query.end, requestedDays);
  const dayOptions = buildDayOptionsBetween(startDate, endDate);
  if (dayOptions.length === 0) {
    const fallbackToday = formatDateInTz(new Date(), userTimeZone);
    dayOptions.push(fallbackToday);
  }
  const { oldest, newest } = getDateBounds(dayOptions);
  const todayStr = formatDateInTz(new Date(), userTimeZone);
  const requestedDate = (req.query.day || '').trim();
  const selectedDate = dayOptions.includes(requestedDate)
    ? requestedDate
    : dayOptions.includes(todayStr)
    ? todayStr
    : newest;

  const totalsByDate = await getTotalsByDate(user.id, oldest, newest);
  const dailyStats = buildDailyStats(dayOptions, totalsByDate, user.daily_goal);

  const todayTotal = totalsByDate.get(todayStr) || 0;
  const goalStatus = !user.daily_goal ? 'unset' : todayTotal <= user.daily_goal ? 'under' : 'over';
  const goalDelta = user.daily_goal ? Math.abs(user.daily_goal - todayTotal) : null;

  const { rows: recentEntries } = await pool.query(
    'SELECT id, entry_date, amount, entry_name, created_at FROM calorie_entries WHERE user_id = $1 AND entry_date = $2 ORDER BY created_at DESC',
    [user.id, selectedDate]
  );
  const viewEntries = recentEntries.map((entry) => ({
    ...entry,
    timeFormatted: entry.created_at ? formatTimeInTz(entry.created_at, userTimeZone) : '',
  }));

  let acceptedLinks = [];
  try {
    acceptedLinks = await getAcceptedLinkUsers(user.id);
  } catch (err) {
    console.error('Failed to load linked users', err);
  }

  let weightEntry = null;
  try {
    weightEntry = await getWeightEntry(user.id, selectedDate);
  } catch (err) {
    console.error('Failed to load weight entry', err);
  }
  const weightTimeFormatted =
    weightEntry && (weightEntry.updated_at || weightEntry.created_at)
      ? formatTimeInTz(weightEntry.updated_at || weightEntry.created_at, userTimeZone)
      : '';
  const viewWeight = weightEntry ? { ...weightEntry, timeFormatted: weightTimeFormatted } : null;

  const sharedViews = [
    {
      userId: user.id,
      email: user.email,
      label: 'You',
      isSelf: true,
      dailyGoal: user.daily_goal,
      dailyStats,
    },
  ];

  for (const link of acceptedLinks) {
    try {
      const totals = await getTotalsByDate(link.userId, oldest, newest);
      const stats = buildDailyStats(dayOptions, totals, link.daily_goal);
      sharedViews.push({
        linkId: link.linkId,
        userId: link.userId,
        email: link.email,
        label: (link.label || '').trim() || link.email,
        isSelf: false,
        dailyGoal: link.daily_goal,
        dailyStats: stats,
      });
    } catch (err) {
      console.error('Failed to build stats for linked user', err);
    }
  }

  res.render('dashboard', {
    user,
    todayTotal,
    goalStatus,
    goalDelta,
    dailyStats,
    dayOptions,
    selectedDate,
    recentEntries: viewEntries,
    sharedViews,
    weightUnit: user.weight_unit || 'lb',
    timeZone: userTimeZone,
    todayStr: todayStrTz,
    range: {
      start: oldest,
      end: newest,
      days: dayOptions.length,
      preset: !req.query.start && !req.query.end ? requestedDays : null,
    },
    weightEntry: viewWeight,
    activePage: 'dashboard',
  });
});

app.get('/entries/day', requireAuth, async (req, res) => {
  const dateStr = (req.query.date || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
    return res.status(400).json({ ok: false, error: 'Invalid date' });
  }

  const targetUserIdRaw = req.query.user ? parseInt(req.query.user, 10) : req.currentUser.id;
  const targetUserId = Number.isNaN(targetUserIdRaw) ? req.currentUser.id : targetUserIdRaw;

  const today = new Date();
  const oldest = new Date(today);
  oldest.setDate(today.getDate() - (MAX_HISTORY_DAYS - 1));
  const oldestStr = toIsoDate(oldest);
  const todayStr = toIsoDate(today);

  if (dateStr < oldestStr || dateStr > todayStr) {
    return res.status(400).json({ ok: false, error: 'Date must be within the last 14 days' });
  }

  if (targetUserId !== req.currentUser.id) {
    try {
      const { rows } = await pool.query(
        `SELECT 1 FROM account_links
          WHERE status = 'accepted'
            AND ((requester_id = $1 AND target_id = $2) OR (requester_id = $2 AND target_id = $1))
          LIMIT 1`,
        [req.currentUser.id, targetUserId]
      );
      if (rows.length === 0) {
        return res.status(403).json({ ok: false, error: 'Not authorized to view entries' });
      }
    } catch (err) {
      console.error('Link check failed', err);
      return res.status(500).json({ ok: false, error: 'Failed to load entries' });
    }
  }

  try {
    const tz = getClientTimezone(req) || req.currentUser?.timezone || 'UTC';
    const { rows } = await pool.query(
      'SELECT id, entry_date, amount, entry_name, created_at FROM calorie_entries WHERE user_id = $1 AND entry_date = $2 ORDER BY created_at DESC',
      [targetUserId, dateStr]
    );

    return res.json({
      ok: true,
      date: dateStr,
      entries: rows.map((row) => ({
        id: row.id,
        date: row.entry_date.toISOString().slice(0, 10),
        time: row.created_at ? formatTimeInTz(row.created_at, tz) : '',
        amount: row.amount,
        name: row.entry_name || null,
      })),
    });
  } catch (err) {
    console.error('Failed to fetch entries for date', err);
    return res.status(500).json({ ok: false, error: 'Failed to load entries' });
  }
});

app.get('/events/entries', requireAuth, (req, res) => {
  const userId = toInt(req.currentUser?.id);
  if (userId === null) {
    return res.sendStatus(401);
  }
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  if (res.flushHeaders) res.flushHeaders();
  res.write('event: ready\ndata: {}\n\n');

  addEntryEventClient(userId, res);
  const keepAlive = setInterval(() => {
    res.write('event: ping\ndata: {}\n\n');
  }, 25000);

  req.on('close', () => {
    clearInterval(keepAlive);
    removeEntryEventClient(userId, res);
    res.end();
  });
});

app.get('/settings/export', requireAuth, async (req, res) => {
  const user = req.currentUser;
  const { rows: entries } = await pool.query(
    'SELECT entry_date, amount, entry_name FROM calorie_entries WHERE user_id = $1 ORDER BY entry_date DESC, id DESC',
    [user.id]
  );

  const { rows: weights } = await pool.query(
    'SELECT entry_date, weight FROM weight_entries WHERE user_id = $1 ORDER BY entry_date DESC, id DESC',
    [user.id]
  );

  const payload = {
    exported_at: new Date().toISOString(),
    user: {
      email: user.email,
      daily_goal: user.daily_goal,
    },
    weights: weights.map((row) => ({
      date: row.entry_date.toISOString().slice(0, 10),
      weight: Number(row.weight),
    })),
    entries: entries.map((row) => ({
      date: row.entry_date.toISOString().slice(0, 10),
      amount: row.amount,
      name: row.entry_name || null,
    })),
  };

  const filename = `schautrack-export-${new Date().toISOString().slice(0, 10)}.json`;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(JSON.stringify(payload, null, 2));
});

app.post('/settings/import', requireAuth, upload.single('import_file'), async (req, res) => {
  if (!req.file || !req.file.buffer) {
    return res.redirect('/settings');
  }

  let parsed;
  try {
    const raw = req.file.buffer.toString('utf8');
    parsed = JSON.parse(raw);
  } catch (err) {
    return res.redirect('/settings');
  }

  const goalCandidate =
    parsed.daily_goal !== undefined ? parsed.daily_goal : parsed.user?.daily_goal;
  const entries = Array.isArray(parsed.entries) ? parsed.entries.slice(0, 500) : [];
  const weights = Array.isArray(parsed.weights) ? parsed.weights.slice(0, 500) : [];

  const toInsert = [];
  entries.forEach((entry) => {
    const dateStr = (entry.date || entry.entry_date || '').toString();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return;
    const { value: amount, ok } = parseAmount(entry.amount);
    if (!ok || amount === 0) return;
    const nameRaw = entry.name || entry.entry_name || '';
    const nameSafe = nameRaw ? String(nameRaw).trim().slice(0, 120) : null;
    toInsert.push({ date: dateStr, amount, name: nameSafe });
  });

  const weightToInsert = [];
  weights.forEach((entry) => {
    const dateStr = (entry.date || entry.entry_date || '').toString();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return;
    const { ok: weightOk, value: weightVal } = parseWeight(entry.weight);
    if (!weightOk || weightVal === null) return;
    weightToInsert.push({ date: dateStr, weight: weightVal });
  });

  try {
    await pool.query('BEGIN');
    await pool.query('DELETE FROM calorie_entries WHERE user_id = $1', [req.currentUser.id]);
    await pool.query('DELETE FROM weight_entries WHERE user_id = $1', [req.currentUser.id]);
    if (Number.isInteger(goalCandidate) && goalCandidate >= 0) {
      await pool.query('UPDATE users SET daily_goal = $1 WHERE id = $2', [
        goalCandidate,
        req.currentUser.id,
      ]);
    }

    for (const entry of toInsert) {
      await pool.query(
        'INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name) VALUES ($1, $2, $3, $4)',
        [req.currentUser.id, entry.date, entry.amount, entry.name]
      );
    }
    for (const w of weightToInsert) {
      await upsertWeightEntry(req.currentUser.id, w.date, w.weight);
    }
    await pool.query('COMMIT');
  } catch (err) {
    console.error('Import failed', err);
    await pool.query('ROLLBACK');
  }

  res.redirect('/settings');
});

app.post('/settings/link/request', requireAuth, async (req, res) => {
  const emailRaw = (req.body.email || '').trim();
  if (!emailRaw) {
    setLinkFeedback(req, 'error', 'Email is required.');
    return res.redirect('/settings');
  }

  try {
    const { rows } = await pool.query('SELECT id, email FROM users WHERE LOWER(email) = LOWER($1)', [
      emailRaw,
    ]);
    const target = rows[0];
    if (!target) {
      setLinkFeedback(req, 'error', 'No account found for that email.');
      return res.redirect('/settings');
    }
    const currentId = toInt(req.currentUser.id);
    const targetId = toInt(target.id);
    if (currentId === null || targetId === null) {
      setLinkFeedback(req, 'error', 'Could not send link request.');
      return res.redirect('/settings');
    }
    if (targetId === currentId) {
      setLinkFeedback(req, 'error', 'You cannot link to your own account.');
      return res.redirect('/settings');
    }

    const existing = await getLinkBetween(currentId, targetId);
    if (existing) {
      if (existing.status === 'accepted') {
        setLinkFeedback(req, 'error', 'You are already linked with this account.');
      } else if (existing.requester_id === req.currentUser.id) {
        setLinkFeedback(req, 'error', 'Request already sent and pending approval.');
      } else {
        setLinkFeedback(req, 'error', 'They already sent you a request. Check incoming requests below.');
      }
      return res.redirect('/settings');
    }

    const myAccepted = await countAcceptedLinks(currentId);
    if (myAccepted >= MAX_LINKS) {
      setLinkFeedback(req, 'error', `You already have ${MAX_LINKS} linked accounts.`);
      return res.redirect('/settings');
    }

    const targetAccepted = await countAcceptedLinks(targetId);
    if (targetAccepted >= MAX_LINKS) {
      setLinkFeedback(req, 'error', 'The other account already reached the linking limit.');
      return res.redirect('/settings');
    }

    await pool.query('INSERT INTO account_links (requester_id, target_id, status) VALUES ($1, $2, $3)', [
      currentId,
      targetId,
      'pending',
    ]);
    setLinkFeedback(req, 'success', `Request sent to ${target.email}.`);
  } catch (err) {
    console.error('Link request error', err);
    setLinkFeedback(req, 'error', 'Could not send link request.');
  }

  return res.redirect('/settings');
});

app.post('/settings/link/respond', requireAuth, async (req, res) => {
  const requestId = parseInt(req.body.request_id, 10);
  const action = (req.body.action || '').trim();
  if (Number.isNaN(requestId) || !['accept', 'decline'].includes(action)) {
    return res.redirect('/settings');
  }

  try {
    const currentId = toInt(req.currentUser.id);
    if (currentId === null) {
      setLinkFeedback(req, 'error', 'Could not update request.');
      return res.redirect('/settings');
    }
    const { rows } = await pool.query(
      'SELECT * FROM account_links WHERE id = $1 AND status = $2 LIMIT 1',
      [requestId, 'pending']
    );
    const request = rows[0];
    if (!request || request.target_id !== currentId) {
      setLinkFeedback(req, 'error', 'Request not found.');
      return res.redirect('/settings');
    }

    if (action === 'accept') {
      const myAccepted = await countAcceptedLinks(currentId);
      if (myAccepted >= MAX_LINKS) {
        setLinkFeedback(req, 'error', `You already have ${MAX_LINKS} linked accounts.`);
        return res.redirect('/settings');
      }
      const requesterAccepted = await countAcceptedLinks(request.requester_id);
      if (requesterAccepted >= MAX_LINKS) {
        setLinkFeedback(req, 'error', 'The requester is already at the link limit.');
        return res.redirect('/settings');
      }

      await pool.query('UPDATE account_links SET status = $1, updated_at = NOW() WHERE id = $2', [
        'accepted',
        requestId,
      ]);
      setLinkFeedback(req, 'success', 'Link request accepted.');
    } else {
      await pool.query('DELETE FROM account_links WHERE id = $1 AND target_id = $2', [
        requestId,
        req.currentUser.id,
      ]);
      setLinkFeedback(req, 'success', 'Request declined.');
    }
  } catch (err) {
    console.error('Link respond error', err);
    setLinkFeedback(req, 'error', 'Could not update request.');
  }

  return res.redirect('/settings');
});

app.post('/settings/link/remove', requireAuth, async (req, res) => {
  const linkId = parseInt(req.body.link_id, 10);
  if (Number.isNaN(linkId)) {
    return res.redirect('/settings');
  }

  try {
    const currentId = toInt(req.currentUser.id);
    if (currentId === null) {
      setLinkFeedback(req, 'error', 'Could not update link.');
      return res.redirect('/settings');
    }
    const { rows } = await pool.query(
      'DELETE FROM account_links WHERE id = $1 AND (requester_id = $2 OR target_id = $2) RETURNING status',
      [linkId, currentId]
    );
    if (rows.length === 0) {
      setLinkFeedback(req, 'error', 'Link not found.');
    } else if (rows[0].status === 'accepted') {
      setLinkFeedback(req, 'success', 'Link removed.');
    } else {
      setLinkFeedback(req, 'success', 'Request cancelled.');
    }
  } catch (err) {
    console.error('Link remove error', err);
    setLinkFeedback(req, 'error', 'Could not update link.');
  }

  return res.redirect('/settings');
});

app.post('/links/:id/label', requireAuth, async (req, res) => {
  const linkId = toInt(req.params.id);
  if (linkId === null) {
    return res.status(400).json({ ok: false, error: 'Invalid link' });
  }
  const rawLabel = typeof req.body.label === 'string' ? req.body.label.trim() : '';
  const label = rawLabel ? rawLabel.slice(0, 120) : null;

  try {
    const { rows } = await pool.query(
      `UPDATE account_links
          SET label = $1, updated_at = NOW()
        WHERE id = $2
          AND status = 'accepted'
          AND (requester_id = $3 OR target_id = $3)
        RETURNING id, label`,
      [label, linkId, req.currentUser.id]
    );
    const updated = rows[0];
    if (!updated) {
      return res.status(404).json({ ok: false, error: 'Link not found' });
    }
    return res.json({ ok: true, label: updated.label || null });
  } catch (err) {
    console.error('Failed to update link label', err);
    return res.status(500).json({ ok: false, error: 'Could not update label' });
  }
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

app.get('/weight/day', requireAuth, async (req, res) => {
  const dateStr = (req.query.date || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
    return res.status(400).json({ ok: false, error: 'Invalid date' });
  }

  const targetUserIdRaw = req.query.user ? parseInt(req.query.user, 10) : req.currentUser.id;
  const targetUserId = Number.isNaN(targetUserIdRaw) ? req.currentUser.id : targetUserIdRaw;

  const today = new Date();
  const oldest = new Date(today);
  oldest.setDate(today.getDate() - (MAX_HISTORY_DAYS - 1));
  const oldestStr = toIsoDate(oldest);
  const todayStr = toIsoDate(today);

  if (dateStr < oldestStr || dateStr > todayStr) {
    return res.status(400).json({ ok: false, error: 'Date outside supported range' });
  }

  if (targetUserId !== req.currentUser.id) {
    try {
      const { rows } = await pool.query(
        `SELECT 1 FROM account_links
          WHERE status = 'accepted'
            AND ((requester_id = $1 AND target_id = $2) OR (requester_id = $2 AND target_id = $1))
          LIMIT 1`,
        [req.currentUser.id, targetUserId]
      );
      if (rows.length === 0) {
        return res.status(403).json({ ok: false, error: 'Not authorized to view weight' });
      }
    } catch (err) {
      console.error('Link check failed', err);
      return res.status(500).json({ ok: false, error: 'Failed to load weight' });
    }
  }

  try {
    const entry = await getWeightEntry(targetUserId, dateStr);
    return res.json({ ok: true, entry });
  } catch (err) {
    console.error('Failed to fetch weight entry', err);
    return res.status(500).json({ ok: false, error: 'Could not load weight' });
  }
});

app.post('/weight/upsert', requireAuth, async (req, res) => {
  const wantsJson = (req.headers.accept || '').includes('application/json');
  const dateStr = (req.body.entry_date || req.body.date || '').trim() || toIsoDate(new Date());
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
  const oldestStr = toIsoDate(oldest);
  const todayStr = toIsoDate(today);
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

app.post('/entries', requireAuth, async (req, res) => {
  const { value: amount, ok: amountOk } = parseAmount(req.body.amount);
  const { ok: weightOk, value: weightVal } = parseWeight(req.body.weight);
  const entryDate = req.body.entry_date || new Date().toISOString().slice(0, 10);
  const entryName = (req.body.entry_name || '').trim();
  const entryNameSafe = entryName ? entryName.slice(0, 120) : null;

  const hasCalorieEntry = amountOk && amount !== 0;
  const hasWeight = weightOk && weightVal !== null;

  if (!hasCalorieEntry && !hasWeight) {
    return res.redirect('/dashboard');
  }

  try {
    await pool.query('BEGIN');

    if (hasCalorieEntry) {
      await pool.query(
        'INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name) VALUES ($1, $2, $3, $4)',
        [req.currentUser.id, entryDate, amount, entryNameSafe]
      );
    }

    if (hasWeight) {
      await upsertWeightEntry(req.currentUser.id, entryDate, weightVal);
    }

    await pool.query('COMMIT');

    if (hasCalorieEntry) {
      await broadcastEntryChange(req.currentUser.id);
    }
  } catch (err) {
    console.error('Failed to add entry', err);
    await pool.query('ROLLBACK').catch(() => {});
  }

  res.redirect('/dashboard');
});

app.post('/entries/:id/update', requireAuth, async (req, res) => {
  const entryId = parseInt(req.params.id, 10);
  const wantsJson = (req.headers.accept || '').includes('application/json');
  const tz = getClientTimezone(req) || req.currentUser?.timezone || 'UTC';

  if (Number.isNaN(entryId)) {
    return wantsJson ? res.status(400).json({ ok: false, error: 'Invalid entry id' }) : res.redirect('/dashboard');
  }

  const updates = [];
  const values = [];
  let idx = 1;

  if (req.body.name !== undefined) {
    const rawName = (req.body.name || '').toString().trim();
    const safeName = rawName ? rawName.slice(0, 120) : null;
    updates.push(`entry_name = $${idx}`);
    values.push(safeName);
    idx += 1;
  }

  if (req.body.amount !== undefined) {
    const { value: amount, ok } = parseAmount(req.body.amount);
    if (!ok || amount === 0) {
      return wantsJson
        ? res.status(400).json({ ok: false, error: 'Invalid amount' })
        : res.redirect('/dashboard');
    }
    updates.push(`amount = $${idx}`);
    values.push(amount);
    idx += 1;
  }

  if (updates.length === 0) {
    return wantsJson
      ? res.status(400).json({ ok: false, error: 'No updates provided' })
      : res.redirect('/dashboard');
  }

  try {
    const { rows } = await pool.query(
      `UPDATE calorie_entries SET ${updates.join(', ')} WHERE id = $${idx} AND user_id = $${idx + 1} RETURNING id, entry_date, amount, entry_name, created_at`,
      [...values, entryId, req.currentUser.id]
    );

    if (rows.length === 0) {
      return wantsJson ? res.status(404).json({ ok: false, error: 'Entry not found' }) : res.redirect('/dashboard');
    }

    const updated = rows[0];
    const payload = {
      id: updated.id,
      date: updated.entry_date.toISOString().slice(0, 10),
      time: updated.created_at ? formatTimeInTz(updated.created_at, tz) : '',
      amount: updated.amount,
      name: updated.entry_name || null,
    };

    await broadcastEntryChange(req.currentUser.id);

    if (wantsJson) {
      return res.json({ ok: true, entry: payload });
    }
  } catch (err) {
    console.error('Failed to update entry', err);
    if (wantsJson) {
      return res.status(500).json({ ok: false, error: 'Update failed' });
    }
  }

  return res.redirect('/dashboard');
});

app.post('/entries/:id/delete', requireAuth, async (req, res) => {
  const entryId = parseInt(req.params.id, 10);
  const wantsJson = (req.headers.accept || '').includes('application/json');
  if (Number.isNaN(entryId)) {
    return wantsJson ? res.status(400).json({ ok: false }) : res.redirect('/dashboard');
  }

  try {
    await pool.query('DELETE FROM calorie_entries WHERE id = $1 AND user_id = $2', [
      entryId,
      req.currentUser.id,
    ]);
    await broadcastEntryChange(req.currentUser.id);
  } catch (err) {
    console.error('Failed to delete entry', err);
    if (wantsJson) {
      return res.status(500).json({ ok: false });
    }
  }

  if (wantsJson) {
    return res.json({ ok: true });
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
app.post('/settings/preferences', requireAuth, async (req, res) => {
  const unitRaw = (req.body.weight_unit || '').toLowerCase();
  const weightUnit = ['kg', 'lb'].includes(unitRaw) ? unitRaw : 'lb';

  try {
    await pool.query('UPDATE users SET weight_unit = $1 WHERE id = $2', [weightUnit, req.currentUser.id]);
  } catch (err) {
    console.error('Failed to update preferences', err);
  }

  res.redirect('/settings');
});

Promise.all([ensureAccountLinksSchema(), ensureWeightEntriesSchema(), ensureUserPrefsSchema()])
  .catch((err) => {
    console.error('Schema init failed', err);
  })
  .finally(() => {
    app.listen(PORT, () => {
      console.log(`Schautrack listening on port ${PORT}`);
    });
  });
