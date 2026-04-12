import { execSync } from 'child_process';
import * as crypto from 'crypto';

const DB_CONTAINER = process.env.DB_CONTAINER || detectDbContainer();
const DB_USER = process.env.POSTGRES_USER || 'schautrack';
const DB_NAME = process.env.POSTGRES_DB || 'schautrack';
const MAILPIT_URL = process.env.MAILPIT_URL || 'http://localhost:8025';

function detectDbContainer(): string {
  try {
    const out = execSync('docker ps --format "{{.Names}}" | grep -E "schautrack.*db"', { encoding: 'utf-8' }).trim();
    const names = out.split('\n').map(n => n.trim()).filter(Boolean);
    // Prefer the test DB container over dev when both are running
    const testDb = names.find(n => n.includes('test'));
    return testDb || names[0] || 'schautrack-test-db-1';
  } catch {
    return 'schautrack-test-db-1';
  }
}

/** Run a SQL query against the test database and return the first line of trimmed output. */
export function psql(sql: string): string {
  const raw = execSync(
    `docker exec -i ${DB_CONTAINER} psql -U ${DB_USER} -d ${DB_NAME} -tA`,
    { input: sql + '\n', encoding: 'utf-8' }
  ).trim();
  // Filter out command tags like "INSERT 0 1", "DELETE 3", "UPDATE 1" etc.
  const lines = raw.split('\n').filter(l => !/^(INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\s/.test(l));
  return lines.join('\n').trim();
}

/** Generate a bcrypt hash for the given password. */
export function bcryptHash(password: string): string {
  return execSync(
    `python3 -c "import bcrypt; print(bcrypt.hashpw(b'${password}', bcrypt.gensalt(10)).decode())"`,
    { encoding: 'utf-8' }
  ).trim();
}

/** Generate a valid TOTP code from a base32 secret.
 *  Waits if we're near the end of a 30s window to avoid edge-case expiry. */
export function generateTOTP(secret: string): string {
  // If less than 5 seconds remain in the current TOTP window, wait for the next one
  const secondsIntoWindow = Math.floor(Date.now() / 1000) % 30;
  if (secondsIntoWindow >= 25) {
    const waitMs = (30 - secondsIntoWindow + 1) * 1000;
    const { execSync } = require('child_process');
    execSync(`sleep ${waitMs / 1000}`);
  }

  // Decode base32 secret
  const base32chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secret.toUpperCase().replace(/=+$/, '')) {
    const val = base32chars.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const key = Buffer.alloc(Math.floor(bits.length / 8));
  for (let i = 0; i < key.length; i++) {
    key[i] = parseInt(bits.substring(i * 8, i * 8 + 8), 2);
  }

  // TOTP: HMAC-SHA1 of time counter
  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / 30);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter & 0xffffffff, 4);

  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24 | hmac[offset + 1] << 16 | hmac[offset + 2] << 8 | hmac[offset + 3]) % 1000000;
  return code.toString().padStart(6, '0');
}

/** Fetch all messages from MailPit, optionally filtered by recipient. */
export async function fetchMailpitMessages(to?: string): Promise<MailpitMessage[]> {
  const query = to ? `?query=to:${encodeURIComponent(to)}` : '';
  const res = await fetch(`${MAILPIT_URL}/api/v1/search${query}`);
  if (!res.ok) throw new Error(`MailPit API error: ${res.status}`);
  const data = await res.json();
  return data.messages || [];
}

/** Extract a 6-digit code from the latest email to a given address. */
export async function extractCodeFromEmail(to: string, retries = 10): Promise<string> {
  for (let i = 0; i < retries; i++) {
    const messages = await fetchMailpitMessages(to);
    if (messages.length > 0) {
      const msg = messages[0];
      // Fetch full message to get body
      const res = await fetch(`${MAILPIT_URL}/api/v1/message/${msg.ID}`);
      if (!res.ok) throw new Error(`MailPit message fetch error: ${res.status}`);
      const full = await res.json();
      const body = full.Text || full.HTML || '';
      const match = body.match(/(\d{6})/);
      if (match) return match[1];
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(`No email with 6-digit code found for ${to} after ${retries} retries`);
}

/** Clear all MailPit messages. */
export async function clearMailpit(): Promise<void> {
  await fetch(`${MAILPIT_URL}/api/v1/messages`, { method: 'DELETE' });
}

const DEFAULT_PASSWORD = 'test1234test';

/**
 * Create or reset an isolated test user for a specific spec file.
 * Returns { email, password, id }. Call in beforeAll() for test isolation.
 * The user gets all features enabled (macros, todos, notes) and clean data.
 */
export function createIsolatedUser(specName: string, opts: { features?: boolean } = {}): { email: string; password: string; id: string } {
  const email = `e2e-${specName}@test.local`;
  const password = DEFAULT_PASSWORD;
  const hash = bcryptHash(password);
  const features = opts.features !== false;

  // Upsert user atomically to avoid race conditions when multiple workers call this simultaneously
  const id = psql(
    `INSERT INTO users (email, password_hash, email_verified)
     VALUES ('${email}', '${hash}', true)
     ON CONFLICT (email) DO UPDATE SET password_hash = '${hash}', email_verified = true, totp_enabled = false, totp_secret = NULL
     RETURNING id`
  );
  psql(`DELETE FROM totp_backup_codes WHERE user_id = ${id}`);
  // Clean all data
  psql(`DELETE FROM calorie_entries WHERE user_id = ${id}`);
  psql(`DELETE FROM weight_entries WHERE user_id = ${id}`);
  psql(`DELETE FROM todo_completions WHERE todo_id IN (SELECT id FROM todos WHERE user_id = ${id})`);
  psql(`DELETE FROM todos WHERE user_id = ${id}`);
  psql(`DELETE FROM daily_notes WHERE user_id = ${id}`);
  psql(`DELETE FROM ai_usage WHERE user_id = ${id}`);

  if (features) {
    psql(`UPDATE users SET
      macros_enabled = '{"calories": true, "protein": true, "carbs": true, "fat": true, "fiber": true, "sugar": true, "auto_calc_calories": false}',
      macro_goals = '{"calories": 2000, "protein": 150, "carbs": 250, "fat": 65, "fiber": 25, "sugar": 50, "calories_mode": "limit", "protein_mode": "target", "carbs_mode": "limit", "fat_mode": "limit"}',
      todos_enabled = true,
      notes_enabled = true,
      daily_goal = 2000
      WHERE id = ${id}`);
  }

  return { email, password, id };
}

/**
 * Login as a specific user via the API (fast, no UI interaction).
 * Uses direct HTTP requests to get a session cookie, then creates a browser context with it.
 */
export async function loginUser(browser: import('@playwright/test').Browser, email: string, password: string): Promise<{ context: import('@playwright/test').BrowserContext; page: import('@playwright/test').Page }> {
  const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';

  // Get CSRF token and session cookie via API
  const csrfRes = await fetch(`${baseURL}/api/csrf`);
  const setCookie = csrfRes.headers.get('set-cookie') || '';
  const sidMatch = setCookie.match(/schautrack\.sid=([^;]+)/);
  const sid = sidMatch ? sidMatch[1] : '';
  const { token } = await csrfRes.json() as { token: string };

  // Login via API
  const loginRes = await fetch(`${baseURL}/api/auth/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': token,
      'Cookie': `schautrack.sid=${sid}`,
    },
    body: JSON.stringify({ email, password }),
  });

  if (!loginRes.ok) {
    const body = await loginRes.text();
    throw new Error(`API login failed (${loginRes.status}): ${body}`);
  }

  // Extract the session cookie from the login response
  const loginSetCookie = loginRes.headers.get('set-cookie') || '';
  const loginSidMatch = loginSetCookie.match(/schautrack\.sid=([^;]+)/);
  const loginSid = loginSidMatch ? loginSidMatch[1] : sid;

  // Create browser context with the session cookie
  const context = await browser.newContext({
    baseURL,
    storageState: {
      cookies: [{
        name: 'schautrack.sid',
        value: loginSid,
        domain: new URL(baseURL).hostname,
        path: '/',
        httpOnly: true,
        secure: false,
        sameSite: 'Lax',
        expires: -1,
      }],
      origins: [],
    },
  });
  const page = await context.newPage();
  return { context, page };
}

interface MailpitMessage {
  ID: string;
  From: { Address: string };
  To: { Address: string }[];
  Subject: string;
  Snippet: string;
}
