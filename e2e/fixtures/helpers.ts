import { execSync } from 'child_process';
import { authenticator } from 'otplib';

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

/** Generate a valid TOTP code from a secret. */
export function generateTOTP(secret: string): string {
  return authenticator.generate(secret);
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
