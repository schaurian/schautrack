// Schautrack server - v1.0.0
require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const multer = require('multer');
const nodemailer = require('nodemailer');
const svgCaptcha = require('svg-captcha');
const rateLimit = require('express-rate-limit');

// Validate required environment variables
if (!process.env.SESSION_SECRET) {
  console.error('FATAL: SESSION_SECRET environment variable is required');
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL environment variable is required');
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
});
const MAX_LINKS = 3;
const MAX_HISTORY_DAYS = 180;
const DEFAULT_RANGE_DAYS = 14;
const userEventClients = new Map(); // userId -> Set(res)
const supportEmail = process.env.SUPPORT_EMAIL || null;
const enableLegal = process.env.ENABLE_LEGAL === 'true';
const configuredBaseUrl = process.env.BASE_URL || null;
const imprintUrl = process.env.IMPRINT_URL || '/imprint';
const imprintAddress = process.env.IMPRINT_ADDRESS || null;
// Display email (image/text)
const imprintEmail = process.env.IMPRINT_EMAIL || null;

// Admin email - user with this email gets admin access
const adminEmail = process.env.ADMIN_EMAIL || null;

// XML escape helper
const escapeXml = (unsafe) => {
  return unsafe.replace(/[<>&'"]/g, (c) => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '\'': return '&apos;';
      case '"': return '&quot;';
    }
  });
};

// Helper to generate text SVG
const textToSvg = (text, color = '#e5e7eb') => {
  if (!text) return '';
  const lines = String(text).split(/\\n|\n/);
  const fontSize = 16;
  const lineHeight = 24;
  const height = lines.length * lineHeight;
  // Estimate width: avg char width approx 9px at 16px font
  const maxLen = Math.max(...lines.map(l => l.length));
  const width = Math.max(maxLen * 10, 100); 
  
  const svgContent = lines.map((line, i) => 
    `<text x="0" y="${(i + 1) * lineHeight - 6}" fill="${color}" font-family="sans-serif" font-weight="500" font-size="${fontSize}">${escapeXml(line)}</text>`
  ).join('');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
    <style>text { font-family: "Space Grotesk", sans-serif; }</style>
    ${svgContent}
  </svg>`;
};
const KG_TO_LB = 2.20462;

// API Key Encryption (AES-256-GCM)
const AI_KEY_ENCRYPTION_SECRET = process.env.AI_KEY_ENCRYPTION_SECRET;

const encryptApiKey = (plaintext) => {
  if (!AI_KEY_ENCRYPTION_SECRET || !plaintext) return null;
  try {
    const key = Buffer.from(AI_KEY_ENCRYPTION_SECRET, 'hex');
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('base64')}:${authTag.toString('base64')}:${encrypted}`;
  } catch (err) {
    console.error('Failed to encrypt API key', err);
    return null;
  }
};

const decryptApiKey = (ciphertext) => {
  if (!AI_KEY_ENCRYPTION_SECRET || !ciphertext) return null;
  try {
    const [ivB64, tagB64, encrypted] = ciphertext.split(':');
    const key = Buffer.from(AI_KEY_ENCRYPTION_SECRET, 'hex');
    const iv = Buffer.from(ivB64, 'base64');
    const authTag = Buffer.from(tagB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    console.error('Failed to decrypt API key', err);
    return null;
  }
};

// AI Provider Configurations
const AI_PROVIDER_CONFIGS = {
  openai: {
    defaultEndpoint: 'https://api.openai.com/v1',
    model: 'gpt-4o-mini',
    authHeader: (key) => ({ 'Authorization': `Bearer ${key}` }),
    formatMessages: (prompt, base64Data, mediaType) => [{
      role: 'user',
      content: [
        { type: 'text', text: prompt },
        {
          type: 'image_url',
          image_url: {
            url: `data:${mediaType};base64,${base64Data}`,
            detail: 'low'
          }
        }
      ]
    }],
    getEndpointPath: () => '/chat/completions',
    parseResponse: (data) => data.choices[0]?.message?.content
  },

  claude: {
    defaultEndpoint: 'https://api.anthropic.com/v1',
    model: null, // No default - must be specified via AI_MODEL
    authHeader: (key) => ({
      'x-api-key': key,
      'anthropic-version': '2023-06-01'
    }),
    formatMessages: (prompt, base64Data, mediaType) => [{
      role: 'user',
      content: [
        {
          type: 'image',
          source: {
            type: 'base64',
            media_type: mediaType,
            data: base64Data
          }
        },
        { type: 'text', text: prompt }
      ]
    }],
    getEndpointPath: () => '/messages',
    parseResponse: (data) => data.content[0]?.text
  },

  ollama: {
    defaultEndpoint: 'http://localhost:11434/v1',
    model: 'gemma3:12b',
    authHeader: (key) => ({ 'Authorization': `Bearer ${key || 'ollama'}` }),
    formatMessages: (prompt, base64Data, mediaType) => [{
      role: 'user',
      content: [
        { type: 'text', text: prompt },
        {
          type: 'image_url',
          image_url: {
            url: `data:${mediaType};base64,${base64Data}`
          }
        }
      ]
    }],
    getEndpointPath: () => '/chat/completions',
    parseResponse: (data) => data.choices[0]?.message?.content
  }
};

// SMTP configuration
const smtpHost = process.env.SMTP_HOST;
const smtpPort = parseInt(process.env.SMTP_PORT || '587', 10);
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const smtpFrom = process.env.SMTP_FROM || supportEmail;
const smtpSecure = process.env.SMTP_SECURE === 'true';

const isSmtpConfigured = () => Boolean(smtpHost && smtpUser && smtpPass && smtpFrom);

let smtpTransporter = null;
if (isSmtpConfigured()) {
  smtpTransporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    auth: {
      user: smtpUser,
      pass: smtpPass,
    },
  });
}

const sendEmail = async (to, subject, text, html) => {
  if (!smtpTransporter) {
    throw new Error('SMTP not configured');
  }
  try {
    return await smtpTransporter.sendMail({
      from: smtpFrom,
      to,
      subject,
      text,
      html,
    });
  } catch (err) {
    // Log SMTP errors but don't expose them to users (privacy protection)
    console.warn('SMTP send failed:', err.message);
    return null;
  }
};

const generateResetCode = () => {
  return crypto.randomBytes(32).toString('hex');
};

// SVG CAPTCHA helper (self-hosted image captcha)
const generateCaptcha = () => {
  return svgCaptcha.create({
    size: 5,
    noise: 4,
    color: true,
    background: '#1a1a2e',
  });
};

const verifyCaptcha = (sessionAnswer, userAnswer) => {
  if (!sessionAnswer || !userAnswer) return false;
  return sessionAnswer.toLowerCase().trim() === userAnswer.toLowerCase().trim();
};

const parseCookies = (header) => {
  if (!header) return {};
  return header.split(';').reduce((acc, part) => {
    const [rawKey, ...rest] = part.split('=');
    const key = rawKey && rawKey.trim();
    if (!key) return acc;
    const value = rest.join('=').trim();
    try {
      acc[key] = decodeURIComponent(value);
    } catch (e) {
      acc[key] = value;
    }
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

// Get the effective timezone for a user
const getUserTimezone = (req, res) => {
  const user = req.currentUser;
  if (user) {
    // Always use the user's saved timezone from database
    return user.timezone || 'UTC';
  }
  // For non-authenticated users, try to detect from client
  return getClientTimezone(req) || 'UTC';
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
  connectionString: process.env.DATABASE_URL,
  max: 20, // maximum pool size
  min: 2,  // minimum pool size  
  idleTimeoutMillis: 30000, // 30 seconds
  connectionTimeoutMillis: 10000, // 10 seconds
});

// Create base tables that other migrations depend on
async function ensureBaseSchema() {
  // Create users table first (many other tables reference it)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      daily_goal INTEGER,
      totp_secret TEXT,
      totp_enabled BOOLEAN DEFAULT FALSE,
      email_verified BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Create calorie_entries table
  await pool.query(`
    CREATE TABLE IF NOT EXISTS calorie_entries (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      entry_date DATE NOT NULL DEFAULT CURRENT_DATE,
      amount INTEGER NOT NULL,
      entry_name TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Create session table for express-session
  await pool.query(`
    CREATE TABLE IF NOT EXISTS "session" (
      "sid" VARCHAR NOT NULL,
      "sess" JSON NOT NULL,
      "expire" TIMESTAMP(6) NOT NULL,
      CONSTRAINT "session_pkey" PRIMARY KEY ("sid")
    );
    CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
  `);
}

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
      ADD COLUMN IF NOT EXISTS label TEXT,
      ADD COLUMN IF NOT EXISTS requester_label TEXT,
      ADD COLUMN IF NOT EXISTS target_label TEXT;
    CREATE UNIQUE INDEX IF NOT EXISTS account_links_pair_idx
      ON account_links (LEAST(requester_id, target_id), GREATEST(requester_id, target_id));
    CREATE INDEX IF NOT EXISTS account_links_requester_idx ON account_links (requester_id);
    CREATE INDEX IF NOT EXISTS account_links_target_idx ON account_links (target_id);
    CREATE INDEX IF NOT EXISTS account_links_status_idx ON account_links (status);
    UPDATE account_links
       SET requester_label = COALESCE(requester_label, label),
           target_label = COALESCE(target_label, label)
     WHERE (requester_label IS NULL OR target_label IS NULL) AND label IS NOT NULL;
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
      ADD COLUMN IF NOT EXISTS weight_unit TEXT,
      ADD COLUMN IF NOT EXISTS timezone_manual BOOLEAN DEFAULT FALSE;
    ALTER TABLE users
      ALTER COLUMN weight_unit SET DEFAULT 'kg';
    UPDATE users SET weight_unit = 'kg' WHERE weight_unit IS NULL;
  `);
}

async function ensureCalorieEntriesSchema() {
  await pool.query(`
    ALTER TABLE calorie_entries
      ADD COLUMN IF NOT EXISTS entry_name TEXT,
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
  `);
}

async function ensurePasswordResetSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx ON password_reset_tokens (user_id);
    CREATE INDEX IF NOT EXISTS password_reset_tokens_expires_idx ON password_reset_tokens (expires_at);
  `);
}

async function ensureEmailVerificationSchema() {
  // First ensure the users table has created_at column
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
  `);

  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_verification_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS email_verification_tokens_user_idx ON email_verification_tokens (user_id);
    CREATE INDEX IF NOT EXISTS email_verification_tokens_expires_idx ON email_verification_tokens (expires_at);
  `);

  // Add new_email column for email change functionality
  await pool.query(`
    ALTER TABLE email_verification_tokens ADD COLUMN IF NOT EXISTS new_email TEXT;
  `);

  // Mark unverified users as verified if they have no pending verification token
  // This handles users created before email verification was added
  await pool.query(`
    UPDATE users SET email_verified = TRUE
    WHERE email_verified = FALSE
      AND id NOT IN (
        SELECT DISTINCT user_id FROM email_verification_tokens
        WHERE used = FALSE AND expires_at > NOW()
      )
  `);
}

async function ensureAdminSettingsSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_settings (
      key TEXT PRIMARY KEY,
      value TEXT,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

async function ensureAIKeysSchema() {
  // Add new unified columns
  await pool.query(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS openai_api_key TEXT,
      ADD COLUMN IF NOT EXISTS claude_api_key TEXT,
      ADD COLUMN IF NOT EXISTS preferred_ai_provider TEXT DEFAULT 'openai',
      ADD COLUMN IF NOT EXISTS ai_key TEXT,
      ADD COLUMN IF NOT EXISTS ai_endpoint TEXT;
  `);

  // Migrate existing keys to unified field
  await pool.query(`
    UPDATE users
    SET ai_key = CASE
      WHEN preferred_ai_provider = 'claude' THEN claude_api_key
      ELSE openai_api_key
    END
    WHERE (openai_api_key IS NOT NULL OR claude_api_key IS NOT NULL)
      AND ai_key IS NULL;
  `);
}

async function ensureAIUsageSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ai_usage (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      usage_date DATE NOT NULL DEFAULT CURRENT_DATE,
      request_count INTEGER NOT NULL DEFAULT 0,
      CONSTRAINT ai_usage_unique UNIQUE (user_id, usage_date)
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS ai_usage_user_date_idx ON ai_usage (user_id, usage_date);
  `);
}

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

async function sendVerificationEmail(email, code) {
  const subject = 'Verify Your Email - Schautrack';
  const text = `Your verification code is: ${code}\n\nThis code expires in 30 minutes.\n\nIf you did not create this account, you can ignore this email.`;
  const html = `
    <p>Your verification code is:</p>
    <h2 style="font-family: monospace; letter-spacing: 4px;">${code}</h2>
    <p>This code expires in 30 minutes.</p>
    <p>If you did not create this account, you can ignore this email.</p>
  `;
  await sendEmail(email, subject, text, html);
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

async function sendEmailChangeVerification(email, code) {
  const subject = 'Verify Your New Email - Schautrack';
  const text = `Your verification code is: ${code}\n\nThis code expires in 30 minutes.\n\nIf you did not request this email change, you can ignore this email.`;
  const html = `
    <p>Your verification code to confirm your new email address is:</p>
    <h2 style="font-family: monospace; letter-spacing: 4px;">${code}</h2>
    <p>This code expires in 30 minutes.</p>
    <p>If you did not request this email change, you can ignore this email.</p>
  `;
  await sendEmail(email, subject, text, html);
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
    const value = safeMathEval(expr);
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return { ok: false, value: 0 };
    }
    return { ok: true, value: Math.round(value) };
  } catch (err) {
    return { ok: false, value: 0 };
  }
}

// Safe mathematical expression evaluator using recursive descent parser
function safeMathEval(expr) {
  let pos = 0;
  
  function peek() {
    return pos < expr.length ? expr[pos] : null;
  }
  
  function consume() {
    return pos < expr.length ? expr[pos++] : null;
  }
  
  function parseNumber() {
    let num = '';
    while (pos < expr.length && /[0-9.]/.test(expr[pos])) {
      num += consume();
    }
    if (num === '' || num === '.') {
      throw new Error('Invalid number');
    }
    return parseFloat(num);
  }
  
  function parseFactor() {
    let ch = peek();
    
    if (ch === '(') {
      consume(); // consume '('
      const result = parseExpression();
      if (consume() !== ')') {
        throw new Error('Missing closing parenthesis');
      }
      return result;
    }
    
    if (ch === '-') {
      consume(); // consume '-'
      return -parseFactor();
    }
    
    if (ch === '+') {
      consume(); // consume '+'
      return parseFactor();
    }
    
    if (/[0-9]/.test(ch)) {
      return parseNumber();
    }
    
    throw new Error('Unexpected character: ' + ch);
  }
  
  function parseTerm() {
    let left = parseFactor();
    
    while (pos < expr.length) {
      const op = peek();
      if (op === '*') {
        consume();
        left *= parseFactor();
      } else if (op === '/') {
        consume();
        const right = parseFactor();
        if (right === 0) {
          throw new Error('Division by zero');
        }
        left /= right;
      } else {
        break;
      }
    }
    
    return left;
  }
  
  function parseExpression() {
    let left = parseTerm();
    
    while (pos < expr.length) {
      const op = peek();
      if (op === '+') {
        consume();
        left += parseTerm();
      } else if (op === '-') {
        consume();
        left -= parseTerm();
      } else {
        break;
      }
    }
    
    return left;
  }
  
  const result = parseExpression();
  if (pos < expr.length) {
    throw new Error('Unexpected character at position ' + pos);
  }
  
  return result;
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

function addUserEventClient(userId, res) {
  if (!userEventClients.has(userId)) {
    userEventClients.set(userId, new Set());
  }
  userEventClients.get(userId).add(res);
}

function removeUserEventClient(userId, res) {
  const set = userEventClients.get(userId);
  if (!set) return;
  set.delete(res);
  if (set.size === 0) {
    userEventClients.delete(userId);
  }
}

function sendUserEvent(userId, eventName, payload) {
  const set = userEventClients.get(userId);
  if (!set || set.size === 0) return;
  const data = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
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
  targets.forEach((targetId) => sendUserEvent(targetId, 'entry-change', payload));
}

async function broadcastLinkLabelChange(linkId, userId, label) {
  const lid = toInt(linkId);
  const uid = toInt(userId);
  if (lid === null || uid === null) return;
  const payload = { linkId: lid, label: label || null };
  sendUserEvent(uid, 'link-label-change', payload);
}

function buildDayOptions(daysToShow) {
  const today = new Date();
  const startDate = new Date(today);
  startDate.setDate(today.getDate() - (daysToShow - 1));
  return buildDayOptionsBetween(startDate, today);
}

function buildDayOptionsBetween(startDateStr, endDateStr) {
  const dayOptions = [];
  // Work with date strings directly to avoid timezone issues
  // Parse as local date by appending time component
  const cursor = new Date(endDateStr + 'T12:00:00');
  const minDate = new Date(startDateStr + 'T12:00:00');
  for (let i = 0; i < MAX_HISTORY_DAYS; i += 1) {
    if (cursor < minDate) break;
    // Format as YYYY-MM-DD without timezone conversion
    const year = cursor.getFullYear();
    const month = String(cursor.getMonth() + 1).padStart(2, '0');
    const day = String(cursor.getDate()).padStart(2, '0');
    dayOptions.push(`${year}-${month}-${day}`);
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

function sanitizeDateRange(startStr, endStr, fallbackDays = DEFAULT_RANGE_DAYS, userTz = 'UTC') {
  const todayStr = formatDateInTz(new Date(), userTz);
  const requestedEnd = endStr && /^\d{4}-\d{2}-\d{2}$/.test(endStr.trim()) ? endStr.trim() : null;
  let endDateStr = requestedEnd && requestedEnd <= todayStr ? requestedEnd : todayStr;

  const requestedStart = startStr && /^\d{4}-\d{2}-\d{2}$/.test(startStr.trim()) ? startStr.trim() : null;

  // Calculate fallback start by subtracting days from end date
  const endDateObj = new Date(endDateStr + 'T12:00:00');
  const fallbackStartObj = new Date(endDateObj);
  fallbackStartObj.setDate(endDateObj.getDate() - (fallbackDays - 1));
  const fallbackStartStr = `${fallbackStartObj.getFullYear()}-${String(fallbackStartObj.getMonth() + 1).padStart(2, '0')}-${String(fallbackStartObj.getDate()).padStart(2, '0')}`;

  let startDateStr = requestedStart || fallbackStartStr;
  if (startDateStr > endDateStr) {
    startDateStr = endDateStr;
  }

  // Calculate max lookback
  const maxLookbackObj = new Date(endDateObj);
  maxLookbackObj.setDate(endDateObj.getDate() - (MAX_HISTORY_DAYS - 1));
  const maxLookbackStr = `${maxLookbackObj.getFullYear()}-${String(maxLookbackObj.getMonth() + 1).padStart(2, '0')}-${String(maxLookbackObj.getDate()).padStart(2, '0')}`;

  if (startDateStr < maxLookbackStr) {
    startDateStr = maxLookbackStr;
  }

  return { startDate: startDateStr, endDate: endDateStr };
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

// Helper functions for admin settings
// Admin settings cache with TTL
let settingsCache = new Map();
let settingsCacheTime = 0;
const SETTINGS_CACHE_TTL = 60000; // 1 minute

const getEffectiveSetting = async (key, envValue) => {
  if (envValue !== undefined && envValue !== null && envValue !== '') {
    return { value: envValue, source: 'env' };
  }

  const now = Date.now();
  
  // Return cached value if still fresh
  if (settingsCache.has(key) && (now - settingsCacheTime) < SETTINGS_CACHE_TTL) {
    return settingsCache.get(key);
  }

  try {
    const result = await pool.query('SELECT value FROM admin_settings WHERE key = $1', [key]);
    let settingResult;
    if (result.rows.length > 0 && result.rows[0].value !== null) {
      settingResult = { value: result.rows[0].value, source: 'db' };
    } else {
      settingResult = { value: null, source: 'none' };
    }
    
    // Cache the result
    settingsCache.set(key, settingResult);
    settingsCacheTime = now;
    
    return settingResult;
  } catch (err) {
    console.error('Failed to get admin setting', key, err);
    return { value: null, source: 'none' };
  }
};

// Helper to invalidate settings cache (call after admin updates)
const invalidateSettingsCache = () => {
  settingsCache.clear();
  settingsCacheTime = 0;
};

const setAdminSetting = async (key, value) => {
  await pool.query(`
    INSERT INTO admin_settings (key, value, updated_at)
    VALUES ($1, $2, NOW())
    ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
  `, [key, value]);
  
  // Invalidate cache after updating settings
  invalidateSettingsCache();
};

// AI usage tracking helpers
const getAIUsageToday = async (userId) => {
  const result = await pool.query(
    'SELECT request_count FROM ai_usage WHERE user_id = $1 AND usage_date = CURRENT_DATE',
    [userId]
  );
  return result.rows[0]?.request_count || 0;
};

const incrementAIUsage = async (userId) => {
  await pool.query(`
    INSERT INTO ai_usage (user_id, usage_date, request_count)
    VALUES ($1, CURRENT_DATE, 1)
    ON CONFLICT (user_id, usage_date) DO UPDATE SET request_count = ai_usage.request_count + 1
  `, [userId]);
};

const getAIDailyLimit = async () => {
  const setting = await getEffectiveSetting('ai_daily_limit', process.env.AI_DAILY_LIMIT);
  const limit = parseInt(setting.value, 10);
  return Number.isNaN(limit) || limit <= 0 ? null : limit; // null means unlimited
};

// Trust proxy headers (X-Forwarded-Proto, X-Forwarded-For, etc.)
// Required for secure cookies behind reverse proxy (nginx, Caddy, etc.)
app.set('trust proxy', true);

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Dynamic robots.txt based on ROBOTS_INDEX environment variable
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  if (process.env.ROBOTS_INDEX === 'true') {
    const host = req.get('host');
    const protocol = req.protocol;
    res.send(`User-agent: *
Allow: /
Disallow: /dashboard
Disallow: /settings
Disallow: /admin
Disallow: /api/

Sitemap: ${protocol}://${host}/sitemap.xml
`);
  } else {
    res.send(`User-agent: *
Disallow: /
`);
  }
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(express.json({ limit: '10mb' }));

app.use(async (req, res, next) => {
  res.locals.buildVersion = process.env.BUILD_VERSION || null;
  res.locals.robotsIndex = process.env.ROBOTS_INDEX === 'true';
  res.locals.baseUrl = configuredBaseUrl || `${req.protocol}://${req.get('host')}`;

  // Load configurable settings (env vars take precedence over DB)
  const effectiveSupportEmail = await getEffectiveSetting('support_email', supportEmail);
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  const effectiveImprintUrl = await getEffectiveSetting('imprint_url', imprintUrl);
  const effectiveImprintAddress = await getEffectiveSetting('imprint_address', imprintAddress);
  const effectiveImprintEmail = await getEffectiveSetting('imprint_email', imprintEmail);

  res.locals.supportEmail = effectiveSupportEmail.value || supportEmail || null;

  // Only enable legal UI if flag is true AND we have the required content
  const legalEnabled = effectiveEnableLegal.value === 'true';
  const hasImprintContent = !!effectiveImprintAddress.value && !!effectiveImprintEmail.value;
  res.locals.enableLegal = legalEnabled && hasImprintContent;
  res.locals.imprintUrl = effectiveImprintUrl.value || '/imprint';
  next();
});

app.use(
  session({
    store: new PgSession({
      pool,
      tableName: 'session',
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7,
      secure: 'auto', // Auto-detect HTTPS from X-Forwarded-Proto header
      sameSite: 'lax',
    },
  })
);

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // max 10 attempts per windowMs
  message: { error: 'Too many attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

const strictLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // max 5 attempts per windowMs
  message: { error: 'Too many attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(async (req, res, next) => {
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
});

// Store detected timezone in cookie for future reference (used for non-authenticated pages)
app.use((req, res, next) => {
  rememberClientTimezone(req, res);
  next();
});

const requireAuth = (req, res, next) => {
  if (!req.currentUser) {
    return res.redirect('/login');
  }
  next();
};

const isAdmin = (user) => {
  return adminEmail && user && user.email.toLowerCase() === adminEmail.toLowerCase();
};

const requireAdmin = (req, res, next) => {
  if (!req.currentUser || !isAdmin(req.currentUser)) {
    return res.status(404).send('Not found');
  }
  next();
};

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
  const hasAiKey = Boolean(user.ai_key);
  let aiKeyLast4 = '';

  if (hasAiKey) {
    const decrypted = decryptApiKey(user.ai_key);
    if (decrypted && decrypted.length >= 4) {
      aiKeyLast4 = decrypted.slice(-4);
    }
  }

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

async function getUserById(id) {
  const { rows } = await pool.query(
    'SELECT id, email, daily_goal, totp_enabled, totp_secret, timezone, weight_unit, timezone_manual, preferred_ai_provider, ai_key, ai_endpoint FROM users WHERE id = $1',
    [id]
  );
  const user = rows[0];
  if (!user) return null;
  return { ...user, id: toInt(user.id) };
}

// SEO: Sitemap for search engines
app.get('/sitemap.xml', (req, res) => {
  const baseUrl = configuredBaseUrl || `${req.protocol}://${req.get('host')}`;
  const pages = [
    { loc: '/', priority: '1.0', changefreq: 'weekly' },
    { loc: '/login', priority: '0.8', changefreq: 'monthly' },
    { loc: '/register', priority: '0.8', changefreq: 'monthly' },
    { loc: '/privacy', priority: '0.5', changefreq: 'yearly' },
    { loc: '/terms', priority: '0.5', changefreq: 'yearly' },
    { loc: '/imprint', priority: '0.3', changefreq: 'yearly' }
  ];

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${pages.map(p => `  <url>
    <loc>${baseUrl}${p.loc}</loc>
    <changefreq>${p.changefreq}</changefreq>
    <priority>${p.priority}</priority>
  </url>`).join('\n')}
</urlset>`;

  res.set('Content-Type', 'application/xml');
  res.send(xml);
});

// Health check endpoint for app verification
app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({
      app: 'schautrack',
      status: 'ok',
      version: process.env.BUILD_VERSION || 'dev'
    });
  } catch {
    res.status(503).json({
      app: 'schautrack',
      status: 'error',
      version: process.env.BUILD_VERSION || 'dev'
    });
  }
});

app.get('/', async (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  const effectiveImprintUrl = await getEffectiveSetting('imprint_url', process.env.IMPRINT_URL);
  res.render('landing', {
    currentUser: null,
    activePage: 'home',
    isAdmin: false,
    enableLegal: effectiveEnableLegal.value === 'true',
    imprintUrl: effectiveImprintUrl.value || '/imprint',
    buildVersion: process.env.BUILD_VERSION || null
  });
});

app.get('/imprint/address.svg', async (req, res) => {
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  const effectiveImprintAddress = await getEffectiveSetting('imprint_address', imprintAddress);
  if (effectiveEnableLegal.value !== 'true' || !effectiveImprintAddress.value) return res.sendStatus(404);
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'no-store');
  res.send(textToSvg(effectiveImprintAddress.value));
});

app.get('/imprint/email.svg', async (req, res) => {
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  const effectiveImprintEmail = await getEffectiveSetting('imprint_email', imprintEmail);
  if (effectiveEnableLegal.value !== 'true' || !effectiveImprintEmail.value) return res.sendStatus(404);
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'no-store');
  res.send(textToSvg(effectiveImprintEmail.value));
});

app.get('/imprint', async (req, res) => {
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  const effectiveImprintAddress = await getEffectiveSetting('imprint_address', imprintAddress);
  const effectiveImprintEmail = await getEffectiveSetting('imprint_email', imprintEmail);
  if (effectiveEnableLegal.value !== 'true' || !effectiveImprintAddress.value || !effectiveImprintEmail.value) return res.sendStatus(404);
  res.render('imprint', { activePage: null });
});

app.get('/privacy', async (req, res) => {
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  if (effectiveEnableLegal.value !== 'true') return res.sendStatus(404);
  res.render('privacy', { activePage: null });
});

app.get('/terms', async (req, res) => {
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  if (effectiveEnableLegal.value !== 'true') return res.sendStatus(404);
  res.render('terms', { activePage: null });
});

app.get('/delete', async (req, res) => {
  const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
  if (effectiveEnableLegal.value !== 'true') return res.sendStatus(404);
  const feedback = req.session.deleteFeedback || null;
  delete req.session.deleteFeedback;
  res.render('delete', { activePage: null, deleteFeedback: feedback });
});

app.get('/register', (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }
  // Clear any pending registration
  delete req.session.pendingRegistration;
  res.render('register', { error: null, email: '', requireCaptcha: false, captchaSvg: null });
});

app.post('/register', authLimiter, async (req, res) => {
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
      const passwordHash = await bcrypt.hash(password, 12);
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

app.get('/login', (req, res) => {
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

app.post('/login', authLimiter, async (req, res) => {
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

    const validPassword = await bcrypt.compare(password, user.password_hash);
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

app.post('/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/forgot-password', (req, res) => {
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

app.post('/forgot-password', strictLimiter, async (req, res) => {
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

app.get('/reset-password', (req, res) => {
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

app.post('/reset-password', async (req, res) => {
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

    const hash = await bcrypt.hash(password, 12);
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
app.get('/verify-email', (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }
  const email = req.session.verifyEmail || '';
  const codeVerified = req.session.verifyCodeVerified || false;

  // If no email in session, redirect to login
  if (!email) {
    return res.redirect('/login');
  }

  res.render('verify-email', { error: null, success: null, email, codeVerified, supportEmail });
});

app.post('/verify-email', async (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }

  const email = req.session.verifyEmail || '';
  const code = (req.body.code || '').trim();

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

app.post('/verify-email/resend', async (req, res) => {
  if (req.currentUser) {
    return res.redirect('/dashboard');
  }

  const email = req.session.verifyEmail || '';

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
  const userTimeZone = getUserTimezone(req, res);
  const serverNow = new Date();
  const todayStrTz = formatDateInTz(serverNow, userTimeZone);
  const requestedRange = parseInt(req.query.range, 10);
  const requestedDays = Number.isInteger(requestedRange)
    ? Math.min(Math.max(requestedRange, 7), MAX_HISTORY_DAYS)
    : DEFAULT_RANGE_DAYS;
  const ignoreCustomRange = Number.isInteger(requestedRange);
  const startParam = ignoreCustomRange ? null : req.query.start;
  const endParam = ignoreCustomRange ? null : req.query.end;
  const { startDate, endDate } = sanitizeDateRange(startParam, endParam, requestedDays, userTimeZone);
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
  const goalThreshold = user.daily_goal ? Math.round(user.daily_goal * 1.1) : null;
  const goalStatus = !user.daily_goal
    ? 'unset'
    : todayTotal <= user.daily_goal
      ? 'under'
      : goalThreshold && todayTotal > goalThreshold
        ? 'over_threshold'
        : 'over';
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
  let lastWeightEntry = null;
  try {
    weightEntry = await getWeightEntry(user.id, selectedDate);
    lastWeightEntry = await getLastWeightEntry(user.id, selectedDate);
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
      todayStr: todayStrTz,
    },
  ];

  for (const link of acceptedLinks) {
    try {
      // Get the linked user's "today" in their timezone
      const linkTodayStr = formatDateInTz(new Date(), link.timezone);
      // Filter out days that haven't started yet in the linked user's timezone
      const linkDayOptions = dayOptions.filter((d) => d <= linkTodayStr);
      const linkOldest = linkDayOptions.length > 0 ? linkDayOptions[linkDayOptions.length - 1] : oldest;
      const linkNewest = linkDayOptions.length > 0 ? linkDayOptions[0] : newest;

      const totals = await getTotalsByDate(link.userId, linkOldest, linkNewest);
      const stats = buildDailyStats(linkDayOptions, totals, link.daily_goal);
      sharedViews.push({
        linkId: link.linkId,
        userId: link.userId,
        email: link.email,
        label: (link.label || '').trim() || link.email,
        isSelf: false,
        dailyGoal: link.daily_goal,
        dailyStats: stats,
        todayStr: linkTodayStr,
      });
    } catch (err) {
      console.error('Failed to build stats for linked user', err);
    }
  }

  // Check if AI estimation is enabled (user or global API key)
  let hasAiEnabled = false;
  let aiUsingGlobalKey = false;
  let aiProviderName = null;

  const userProvider = user.ai_provider;
  const globalKey = await getEffectiveSetting('ai_key', process.env.AI_KEY);
  const globalProvider = await getEffectiveSetting('ai_provider', process.env.AI_PROVIDER);

  if (user.ai_key) {
    hasAiEnabled = true;
    aiProviderName = userProvider || globalProvider.value || 'openai';
  } else {
    // AI is enabled if provider is set and requirements are met
    if (globalProvider.value) {
      if (globalProvider.value === 'ollama') {
        // Ollama just needs to be configured
        hasAiEnabled = true;
        aiUsingGlobalKey = true;
        aiProviderName = 'ollama';
      } else if (globalKey.value) {
        // OpenAI/Claude need API key
        hasAiEnabled = true;
        aiUsingGlobalKey = true;
        aiProviderName = globalProvider.value;
      }
    }
  }

  // Get AI usage info if using global key
  let aiUsage = null;
  if (hasAiEnabled && aiUsingGlobalKey) {
    const dailyLimit = await getAIDailyLimit();
    if (dailyLimit !== null) {
      const usageToday = await getAIUsageToday(user.id);
      aiUsage = {
        used: usageToday,
        limit: dailyLimit,
        remaining: Math.max(0, dailyLimit - usageToday),
      };
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
    weightUnit: user.weight_unit || 'kg',
    timeZone: userTimeZone,
    todayStr: todayStrTz,
    range: {
      start: oldest,
      end: newest,
      days: dayOptions.length,
      preset: !req.query.start && !req.query.end ? requestedDays : null,
    },
    weightEntry: viewWeight,
    lastWeightEntry,
    hasAiEnabled,
    aiUsage,
    aiProviderName,
    activePage: 'dashboard',
  });
});

app.get('/overview', requireAuth, async (req, res) => {
  const requestedRange = parseInt(req.query.range, 10);
  const rangeDays = Number.isInteger(requestedRange)
    ? Math.min(Math.max(requestedRange, 7), MAX_HISTORY_DAYS)
    : DEFAULT_RANGE_DAYS;

  const targetUserIdRaw = req.query.user ? parseInt(req.query.user, 10) : req.currentUser.id;
  const targetUserId = Number.isNaN(targetUserIdRaw) ? req.currentUser.id : targetUserIdRaw;

  // Fetch target user early to get their timezone
  const targetUser =
    targetUserId === req.currentUser.id ? req.currentUser : await getUserById(targetUserId);

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
        return res.status(403).json({ ok: false, error: 'Not authorized' });
      }
    } catch (err) {
      console.error('Link check failed for overview', err);
      return res.status(500).json({ ok: false, error: 'Failed to load overview' });
    }
  }

  // Use viewer's timezone for building the date range
  const viewerTz = getUserTimezone(req, res);
  // Use target user's timezone to determine their "today"
  const targetTz = targetUser?.timezone || 'UTC';

  const { startDate, endDate } = sanitizeDateRange(req.query.start, req.query.end, rangeDays, viewerTz);
  let dayOptions = buildDayOptionsBetween(startDate, endDate);

  // For linked users, filter out days that haven't started yet in their timezone
  if (targetUserId !== req.currentUser.id) {
    const targetTodayStr = formatDateInTz(new Date(), targetTz);
    dayOptions = dayOptions.filter((d) => d <= targetTodayStr);
  }

  if (dayOptions.length === 0) {
    const fallbackToday = formatDateInTz(new Date(), targetTz);
    dayOptions.push(fallbackToday);
  }
  const { oldest, newest } = getDateBounds(dayOptions);
  const todayStrTz = formatDateInTz(new Date(), targetTz);

  try {
    const dailyGoal = targetUser?.daily_goal || null;
    const totalsByDate = await getTotalsByDate(targetUserId, oldest, newest);
    const dailyStats = buildDailyStats(dayOptions, totalsByDate, dailyGoal);
    const todayTotal = totalsByDate.get(todayStrTz) || 0;
    const goalThreshold = dailyGoal ? Math.round(dailyGoal * 1.1) : null;
    const goalStatus = !dailyGoal
      ? 'unset'
      : todayTotal <= dailyGoal
        ? 'under'
        : goalThreshold && todayTotal > goalThreshold
          ? 'over_threshold'
          : 'over';
    const goalDelta = dailyGoal ? Math.abs(dailyGoal - todayTotal) : null;

    return res.json({
      ok: true,
      userId: targetUserId,
      dailyGoal,
      todayTotal,
      todayStr: todayStrTz,
      goalStatus,
      goalDelta,
      dailyStats,
      dayOptions,
      range: { start: oldest, end: newest },
    });
  } catch (err) {
    console.error('Failed to build overview', err);
    return res.status(500).json({ ok: false, error: 'Failed to load overview' });
  }
});

app.get('/entries/day', requireAuth, async (req, res) => {
  const dateStr = (req.query.date || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
    return res.status(400).json({ ok: false, error: 'Invalid date' });
  }

  const targetUserIdRaw = req.query.user ? parseInt(req.query.user, 10) : req.currentUser.id;
  const targetUserId = Number.isNaN(targetUserIdRaw) ? req.currentUser.id : targetUserIdRaw;

  // Fetch target user early to get their timezone for timestamp display
  const targetUser =
    targetUserId === req.currentUser.id ? req.currentUser : await getUserById(targetUserId);

  // Use viewer's timezone for date range validation (matches the dots shown in UI)
  const viewerTz = getUserTimezone(req, res);
  // Use target user's timezone for displaying entry timestamps
  const displayTz = targetUserId === req.currentUser.id
    ? viewerTz
    : (targetUser?.timezone || 'UTC');

  const today = new Date();
  const oldest = new Date(today);
  oldest.setDate(today.getDate() - (MAX_HISTORY_DAYS - 1));
  const oldestStr = formatDateInTz(oldest, viewerTz);
  const todayStr = formatDateInTz(today, viewerTz);

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
        time: row.created_at ? formatTimeInTz(row.created_at, displayTz) : '',
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

  addUserEventClient(userId, res);
  const keepAlive = setInterval(() => {
    res.write('event: ping\ndata: {}\n\n');
  }, 25000);

  req.on('close', () => {
    clearInterval(keepAlive);
    removeUserEventClient(userId, res);
    res.end();
  });
});

app.get('/settings/export', requireAuth, async (req, res) => {
  const user = req.currentUser;
  const { rows: entries } = await pool.query(
    'SELECT entry_date, amount, entry_name, created_at FROM calorie_entries WHERE user_id = $1 ORDER BY entry_date DESC, id DESC',
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
      created_at: row.created_at ? row.created_at.toISOString() : null,
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
    const createdAt = entry.created_at ? new Date(entry.created_at) : null;
    toInsert.push({ date: dateStr, amount, name: nameSafe, created_at: createdAt });
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
      if (entry.created_at) {
        await pool.query(
          'INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name, created_at) VALUES ($1, $2, $3, $4, $5)',
          [req.currentUser.id, entry.date, entry.amount, entry.name, entry.created_at]
        );
      } else {
        await pool.query(
          'INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name) VALUES ($1, $2, $3, $4)',
          [req.currentUser.id, entry.date, entry.amount, entry.name]
        );
      }
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
          SET requester_label = CASE WHEN requester_id = $3 THEN $1 ELSE requester_label END,
              target_label = CASE WHEN target_id = $3 THEN $1 ELSE target_label END,
              updated_at = NOW()
        WHERE id = $2
          AND status = 'accepted'
          AND ($3 = requester_id OR $3 = target_id)
        RETURNING id,
          CASE WHEN requester_id = $3 THEN requester_label ELSE target_label END AS label,
          $3::int AS actor_id`,
      [label, linkId, req.currentUser.id]
    );
    const updated = rows[0];
    if (!updated) {
      return res.status(404).json({ ok: false, error: 'Link not found' });
    }
    await broadcastLinkLabelChange(updated.id, updated.actor_id, updated.label);
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

  // Fetch target user early to get their timezone
  const targetUser =
    targetUserId === req.currentUser.id ? req.currentUser : await getUserById(targetUserId);

  // Use target user's timezone for linked users, viewer's timezone for self
  const tz = targetUserId === req.currentUser.id
    ? getUserTimezone(req, res)
    : (targetUser?.timezone || 'UTC');

  const today = new Date();
  const oldest = new Date(today);
  oldest.setDate(today.getDate() - (MAX_HISTORY_DAYS - 1));
  const oldestStr = formatDateInTz(oldest, tz);
  const todayStr = formatDateInTz(today, tz);

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
    const lastWeight = await getLastWeightEntry(targetUserId, dateStr);
    return res.json({ ok: true, entry, lastWeight });
  } catch (err) {
    console.error('Failed to fetch weight entry', err);
    return res.status(500).json({ ok: false, error: 'Could not load weight' });
  }
});

app.post('/weight/upsert', requireAuth, async (req, res) => {
  const wantsJson = (req.headers.accept || '').includes('application/json');
  const userTz = getUserTimezone(req, res);
  const dateStr = (req.body.entry_date || req.body.date || '').trim() || formatDateInTz(new Date(), userTz);
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
  const oldestStr = formatDateInTz(oldest, userTz);
  const todayStr = formatDateInTz(today, userTz);
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
  const wantsJson = (req.headers.accept || '').includes('application/json');
  const userTz = getUserTimezone(req, res);
  const { value: amount, ok: amountOk } = parseAmount(req.body.amount);
  const { ok: weightOk, value: weightVal } = parseWeight(req.body.weight);
  const entryDate = req.body.entry_date || formatDateInTz(new Date(), userTz);
  const entryName = (req.body.entry_name || '').trim();
  const entryNameSafe = entryName ? entryName.slice(0, 120) : null;

  const hasCalorieEntry = amountOk && amount !== 0;
  const hasWeight = weightOk && weightVal !== null;

  if (!hasCalorieEntry && !hasWeight) {
    if (wantsJson) {
      return res.status(400).json({ ok: false, error: 'Invalid entry data' });
    }
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

    if (wantsJson) {
      return res.json({ ok: true });
    }
  } catch (err) {
    console.error('Failed to add entry', err);
    await pool.query('ROLLBACK').catch(() => {});
    if (wantsJson) {
      return res.status(500).json({ ok: false, error: 'Failed to save entry' });
    }
  }

  res.redirect('/dashboard');
});

app.post('/entries/:id/update', requireAuth, async (req, res) => {
  const entryId = parseInt(req.params.id, 10);
  const wantsJson = (req.headers.accept || '').includes('application/json');
  const tz = getUserTimezone(req, res);

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

app.post('/weight/:id/delete', requireAuth, async (req, res) => {
  const weightId = parseInt(req.params.id, 10);
  const wantsJson = (req.headers.accept || '').includes('application/json');
  if (Number.isNaN(weightId)) {
    return wantsJson ? res.status(400).json({ ok: false }) : res.redirect('/dashboard');
  }

  try {
    await pool.query('DELETE FROM weight_entries WHERE id = $1 AND user_id = $2', [
      weightId,
      req.currentUser.id,
    ]);
    await broadcastEntryChange(req.currentUser.id);
  } catch (err) {
    console.error('Failed to delete weight entry', err);
    if (wantsJson) {
      return res.status(500).json({ ok: false });
    }
  }

  if (wantsJson) {
    return res.json({ ok: true });
  }
  res.redirect('/dashboard');
});

// AI Calorie Estimation API
app.post('/api/ai/estimate', strictLimiter, requireAuth, async (req, res) => {
  const { image, context } = req.body;

  if (!image || !image.startsWith('data:image/')) {
    return res.status(400).json({ ok: false, error: 'Invalid image data' });
  }

  const user = req.currentUser;

  // Determine provider from global setting only
  const globalProvider = await getEffectiveSetting('ai_provider', process.env.AI_PROVIDER);
  const provider = globalProvider.value;

  if (!provider) {
    return res.status(400).json({ ok: false, error: 'AI_PROVIDER must be configured (openai, claude, or ollama)' });
  }

  if (!['openai', 'claude', 'ollama'].includes(provider)) {
    return res.status(400).json({ ok: false, error: 'Invalid provider' });
  }

  // Get unified API key and endpoint
  let apiKey = null;
  let endpoint = null;
  let usingGlobalKey = false;

  // User's personal key
  if (user.ai_key) {
    apiKey = decryptApiKey(user.ai_key);
  }

  // User's custom endpoint
  if (user.ai_endpoint) {
    endpoint = user.ai_endpoint;
  }

  // Fallback to global settings
  if (!apiKey) {
    const globalKey = await getEffectiveSetting('ai_key', process.env.AI_KEY);
    if (globalKey.value) {
      apiKey = globalKey.value;
      usingGlobalKey = true;
    }
  }

  if (!endpoint) {
    const globalEndpoint = await getEffectiveSetting('ai_endpoint', process.env.AI_ENDPOINT);
    if (globalEndpoint.value) {
      endpoint = globalEndpoint.value;
    }
  }

  // Provider-specific validation
  if (provider === 'openai' || provider === 'claude') {
    // OpenAI and Claude require API key
    if (!apiKey) {
      return res.status(400).json({
        ok: false,
        error: `${provider === 'openai' ? 'OpenAI' : 'Claude'} requires an API key. Please configure AI_KEY.`
      });
    }
  }

  if (provider === 'ollama') {
    // Ollama requires endpoint
    if (!endpoint) {
      return res.status(400).json({
        ok: false,
        error: 'Ollama requires AI_ENDPOINT to be configured (e.g., http://ollama:11434/v1)'
      });
    }
    // Ollama: API key is optional
    if (!apiKey) {
      apiKey = 'ollama';
      usingGlobalKey = true; // Count Ollama usage as global
    }
  }

  // Rate limiting: only applies when using global key
  if (usingGlobalKey) {
    const dailyLimit = await getAIDailyLimit();
    if (dailyLimit !== null) {
      const usageToday = await getAIUsageToday(user.id);
      if (usageToday >= dailyLimit) {
        return res.status(429).json({
          ok: false,
          error: `Daily limit reached (${dailyLimit} requests). Add your own API key in settings for unlimited access.`,
          limitReached: true,
          limit: dailyLimit,
          used: usageToday,
        });
      }
    }
  }

  const base64Data = image.replace(/^data:image\/\w+;base64,/, '');
  const mediaType = image.match(/^data:(image\/\w+);base64,/)?.[1] || 'image/jpeg';

  // Get custom model from settings/env
  let customModel = null;
  const globalModel = await getEffectiveSetting('ai_model', process.env.AI_MODEL);
  if (globalModel.value) {
    customModel = globalModel.value;
  }

  // Provider-specific model validation
  if (provider === 'openai' || provider === 'claude') {
    if (!customModel) {
      return res.status(400).json({
        ok: false,
        error: `${provider === 'openai' ? 'OpenAI' : 'Claude'} requires AI_MODEL to be configured (e.g., ${provider === 'openai' ? 'gpt-4o-mini' : 'claude-sonnet-4-20250514'})`
      });
    }
  }

  const contextHint = context ? `\n\nUser provided context: "${context}"` : '';
  const prompt = `Analyze this food image and estimate the calories.${contextHint}

Respond in JSON format with these fields:
- calories: estimated total calories (number, must be > 0 if food is detected). Round to nearest 50 for values >= 50.
- food: brief description of the food items (string, max 50 chars)
- confidence: your confidence level ("high", "medium", or "low")

If you cannot identify any food in the image, set calories to 0 and food to "No food detected".

Only respond with the JSON object, no other text.`;

  try {
    const result = await callAIProvider(
      provider,
      apiKey,
      endpoint,
      base64Data,
      mediaType,
      prompt,
      customModel
    );

    // Increment usage after successful request (only for global key)
    if (usingGlobalKey) {
      await incrementAIUsage(user.id);
    }

    // Round calories: keep exact if <50, otherwise round to nearest 50
    const rawCalories = result.calories;
    const calories = rawCalories < 50 ? rawCalories : Math.round(rawCalories / 50) * 50;

    return res.json({
      ok: true,
      calories,
      food: result.food,
      confidence: result.confidence,
    });
  } catch (err) {
    console.error('AI estimation failed:', err.message);
    if (err.message === 'NO_FOOD_DETECTED') {
      return res.status(400).json({
        ok: false,
        error: 'Could not identify food in the image. Try taking a clearer photo or use manual entry.',
        code: 'NO_FOOD',
      });
    }
    return res.status(500).json({ ok: false, error: err.message || 'AI analysis failed' });
  }
});

async function callAIProvider(providerName, apiKey, endpoint, base64Data, mediaType, prompt, customModel = null) {
  const config = AI_PROVIDER_CONFIGS[providerName];
  if (!config) throw new Error(`Unknown provider: ${providerName}`);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 600000); // 10 minutes

  try {
    const messages = config.formatMessages(prompt, base64Data, mediaType);
    const body = {
      model: customModel || config.model, // Use custom model if provided, otherwise use default
      messages: messages,
      max_tokens: 200
    };

    const baseUrl = endpoint || config.defaultEndpoint;
    const url = `${baseUrl}${config.getEndpointPath()}`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        ...config.authHeader(apiKey),
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`${providerName} API error (${response.status}): ${errorText}`);
    }

    const data = await response.json();
    const content = config.parseResponse(data);

    if (!content) {
      throw new Error(`No content in ${providerName} response`);
    }

    return parseAIResponse(content);
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error('Request timed out. Please try again.');
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

function parseAIResponse(content) {
  if (!content || typeof content !== 'string') {
    throw new Error('Empty AI response');
  }

  // Remove markdown code blocks if present
  let cleaned = content.replace(/```json\s*/gi, '').replace(/```\s*/g, '').trim();

  const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    console.error('AI response without JSON:', content);
    throw new Error('Could not parse AI response');
  }

  try {
    const parsed = JSON.parse(jsonMatch[0]);

    const calories = parseInt(parsed.calories, 10);
    if (isNaN(calories) || calories <= 0) {
      // AI couldn't identify food - return specific error
      const reason = parsed.food || 'No food detected';
      const noFoodError = new Error('NO_FOOD_DETECTED');
      noFoodError.reason = reason;
      throw noFoodError;
    }

    return {
      calories,
      food: String(parsed.food || 'Unknown food').slice(0, 50),
      confidence: ['high', 'medium', 'low'].includes(parsed.confidence) ? parsed.confidence : 'medium',
    };
  } catch (parseErr) {
    if (parseErr.message === 'NO_FOOD_DETECTED') {
      throw parseErr;
    }
    console.error('JSON parse error:', parseErr.message, 'Content:', content);
    throw new Error('Could not understand AI response');
  }
}

app.get('/2fa', requireAuth, (req, res) => res.redirect('/settings'));

app.get('/2fa/setup', requireAuth, async (req, res) => {
  const user = req.currentUser;
  const secret = speakeasy.generateSecret({
    name: `Schautrack (${user.email})`,
  });

  req.session.tempSecret = secret.base32;
  req.session.tempUrl = secret.otpauth_url;
  req.session.tempSecretCreatedAt = Date.now();
  res.redirect('/settings');
});

app.get('/2fa/cancel', requireAuth, (req, res) => {
  delete req.session.tempSecret;
  delete req.session.tempUrl;
  delete req.session.tempSecretCreatedAt;
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
    delete req.session.tempSecretCreatedAt;
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

app.post('/settings/ai', requireAuth, async (req, res) => {
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

app.post('/settings/password', requireAuth, async (req, res) => {
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

    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      req.session.passwordFeedback = { type: 'error', message: 'Current password is incorrect.' };
      return res.redirect('/settings');
    }

    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.currentUser.id]);

    req.session.passwordFeedback = { type: 'success', message: 'Password updated successfully.' };
    res.redirect('/settings');
  } catch (err) {
    console.error('Password change error', err);
    req.session.passwordFeedback = { type: 'error', message: 'Could not change password. Please try again.' };
    res.redirect('/settings');
  }
});

// Email change routes
app.post('/settings/email/request', strictLimiter, requireAuth, async (req, res) => {
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

    const validPassword = await bcrypt.compare(password, user.password_hash);
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

app.get('/settings/email/verify', requireAuth, (req, res) => {
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

app.post('/settings/email/verify', requireAuth, async (req, res) => {
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

app.post('/settings/email/cancel', requireAuth, (req, res) => {
  delete req.session.pendingEmailChange;
  delete req.session.emailChangeAttempts;
  res.redirect('/settings');
});

// Admin routes
app.get('/admin', requireAuth, requireAdmin, async (req, res) => {
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

app.post('/admin/settings', requireAuth, requireAdmin, async (req, res) => {
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

app.post('/admin/users/:id/delete', requireAuth, requireAdmin, async (req, res) => {
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
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);
    req.session.adminFeedback = { type: 'success', message: 'User deleted.' };
  } catch (err) {
    console.error('Failed to delete user', err);
    req.session.adminFeedback = { type: 'error', message: 'Failed to delete user.' };
  }
  res.redirect('/admin');
});

// Retry schema initialization with exponential backoff
async function initSchemaWithRetry(maxRetries = 10, initialDelay = 1000) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      // First create base tables (users, calorie_entries, session)
      // These must exist before other migrations that ALTER or reference them
      await ensureBaseSchema();

      // Then run all other migrations in parallel
      await Promise.all([
        ensureAccountLinksSchema(),
        ensureWeightEntriesSchema(),
        ensureUserPrefsSchema(),
        ensureCalorieEntriesSchema(),
        ensurePasswordResetSchema(),
        ensureEmailVerificationSchema(),
        ensureAdminSettingsSchema(),
        ensureAIKeysSchema(),
        ensureAIUsageSchema()
      ]);
      console.log('Schema initialization successful');
      return;
    } catch (err) {
      const delay = initialDelay * Math.pow(2, attempt - 1);
      console.error(`Schema init failed (attempt ${attempt}/${maxRetries}):`, err.message);
      if (attempt < maxRetries) {
        console.log(`Retrying in ${delay}ms...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      } else {
        console.error('Schema initialization failed after all retries. App will start but may have issues.');
      }
    }
  }
}

// Validate AI configuration at startup
async function validateAIConfig() {
  const provider = await getEffectiveSetting('ai_provider', process.env.AI_PROVIDER);

  // If no provider is set, skip AI validation (AI features are disabled)
  if (!provider.value) {
    return;
  }

  // Validate provider is valid
  if (!['openai', 'claude', 'ollama'].includes(provider.value)) {
    console.error('');
    console.error('═══════════════════════════════════════════════════════════════');
    console.error('  STARTUP ERROR: Invalid AI Configuration');
    console.error('═══════════════════════════════════════════════════════════════');
    console.error('');
    console.error(`  AI_PROVIDER is set to '${provider.value}' but must be one of: openai, claude, ollama`);
    console.error('');
    console.error('═══════════════════════════════════════════════════════════════');
    console.error('');
    process.exit(1);
  }

  // OpenAI and Claude require API key + model
  if (provider.value === 'openai' || provider.value === 'claude') {
    const apiKey = await getEffectiveSetting('ai_key', process.env.AI_KEY);
    const model = await getEffectiveSetting('ai_model', process.env.AI_MODEL);

    const providerName = provider.value === 'openai' ? 'OpenAI' : 'Claude';
    const exampleModel = provider.value === 'openai' ? 'gpt-4o-mini' : 'claude-sonnet-4-20250514';

    if (!apiKey.value || !model.value) {
      console.error('');
      console.error('═══════════════════════════════════════════════════════════════');
      console.error('  STARTUP ERROR: Invalid AI Configuration');
      console.error('═══════════════════════════════════════════════════════════════');
      console.error('');
      console.error(`  AI_PROVIDER is set to '${provider.value}' but required configuration is missing:`);
      console.error('');
      if (!apiKey.value) console.error('  ✗ AI_KEY is not set');
      if (!model.value) console.error('  ✗ AI_MODEL is not set');
      console.error('');
      console.error(`  ${providerName} requires both AI_KEY and AI_MODEL to be configured.`);
      console.error('');
      console.error('  Example configuration:');
      console.error(`    AI_PROVIDER=${provider.value}`);
      console.error(`    AI_KEY=sk-...`);
      console.error(`    AI_MODEL=${exampleModel}`);
      console.error('');
      console.error('  Please set these in your environment variables or .env file.');
      console.error('');
      console.error('═══════════════════════════════════════════════════════════════');
      console.error('');
      process.exit(1);
    }
  }

  // Ollama requires endpoint
  if (provider.value === 'ollama') {
    const endpoint = await getEffectiveSetting('ai_endpoint', process.env.AI_ENDPOINT);

    if (!endpoint.value) {
      console.error('');
      console.error('═══════════════════════════════════════════════════════════════');
      console.error('  STARTUP ERROR: Invalid AI Configuration');
      console.error('═══════════════════════════════════════════════════════════════');
      console.error('');
      console.error(`  AI_PROVIDER is set to 'ollama' but AI_ENDPOINT is not configured.`);
      console.error('');
      console.error('  Ollama requires AI_ENDPOINT to be set.');
      console.error('');
      console.error('  Example configuration:');
      console.error('    AI_PROVIDER=ollama');
      console.error('    AI_ENDPOINT=http://ollama:11434/v1');
      console.error('');
      console.error('  Please set AI_ENDPOINT in your environment variables or .env file.');
      console.error('');
      console.error('═══════════════════════════════════════════════════════════════');
      console.error('');
      process.exit(1);
    }
  }
}

initSchemaWithRetry()
  .then(() => validateAIConfig())
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Schautrack listening on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Startup failed:', err);
    process.exit(1);
  });
