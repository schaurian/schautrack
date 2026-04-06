import { execSync } from 'child_process';
import * as crypto from 'crypto';

const DB_CONTAINER = process.env.DB_CONTAINER || detectDbContainer();
const DB_USER = process.env.POSTGRES_USER || 'schautrack';
const DB_NAME = process.env.POSTGRES_DB || 'schautrack';
const MAILPIT_URL = process.env.MAILPIT_URL || 'http://localhost:8025';

function detectDbContainer(): string {
  try {
    const out = execSync('docker ps --format "{{.Names}}" | grep -E "schautrack.*db"', { encoding: 'utf-8' }).trim();
    return out.split('\n')[0];
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

/** Generate a valid TOTP code from a base32 secret. */
export function generateTOTP(secret: string): string {
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

interface MailpitMessage {
  ID: string;
  From: { Address: string };
  To: { Address: string }[];
  Subject: string;
  Snippet: string;
}
