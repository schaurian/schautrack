/**
 * Creates/resets test users in the E2E test database.
 * Works with both compose.dev.yml and compose.test.yml.
 */
import { execSync } from 'child_process';

const DB_CONTAINER = process.env.DB_CONTAINER || detectDbContainer();
const DB_USER = process.env.POSTGRES_USER || 'schautrack';
const DB_NAME = process.env.POSTGRES_DB || 'schautrack';

function detectDbContainer(): string {
  try {
    const out = execSync('docker ps --format "{{.Names}}" | grep -E "schautrack.*db"', { encoding: 'utf-8' }).trim();
    return out.split('\n')[0];
  } catch {
    return 'schautrack-db-1';
  }
}

function psql(sql: string): string {
  return execSync(
    `docker exec -i ${DB_CONTAINER} psql -U ${DB_USER} -d ${DB_NAME} -tA`,
    { input: sql + '\n', encoding: 'utf-8' }
  ).trim();
}

function bcryptHash(password: string): string {
  return execSync(
    `python3 -c "import bcrypt; print(bcrypt.hashpw(b'${password}', bcrypt.gensalt(10)).decode())"`,
    { encoding: 'utf-8' }
  ).trim();
}

function ensureUser(email: string, password: string, opts: { verified?: boolean; admin?: boolean; features?: boolean } = {}) {
  const hash = bcryptHash(password);
  const verified = opts.verified !== false;
  const exists = psql(`SELECT id FROM users WHERE email = '${email}'`);

  if (exists) {
    psql(`UPDATE users SET password_hash = '${hash}', email_verified = ${verified}, totp_enabled = false, totp_secret = NULL WHERE email = '${email}'`);
    // Clean up 2FA state
    psql(`DELETE FROM totp_backup_codes WHERE user_id = ${exists}`);
    console.log(`User reset: ${email} (id: ${exists})`);
  } else {
    psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${email}', '${hash}', ${verified})`);
    const id = psql(`SELECT id FROM users WHERE email = '${email}'`);
    console.log(`User created: ${email} (id: ${id})`);
  }

  if (opts.features) {
    psql(`UPDATE users SET
      macros_enabled = '{"calories": true, "protein": true, "carbs": true, "fat": true, "fiber": true, "sugar": true}',
      macro_goals = '{"calories": 2000, "protein": 150, "carbs": 250, "fat": 65, "fiber": 25, "sugar": 50, "calories_mode": "limit", "protein_mode": "target", "carbs_mode": "limit", "fat_mode": "limit"}',
      todos_enabled = true,
      notes_enabled = true
      WHERE email = '${email}'`);
  }
}

function cleanupTestData(email: string) {
  const id = psql(`SELECT id FROM users WHERE email = '${email}'`);
  if (!id) return;
  psql(`DELETE FROM calorie_entries WHERE user_id = ${id}`);
  psql(`DELETE FROM weight_entries WHERE user_id = ${id}`);
  psql(`DELETE FROM todo_completions WHERE todo_id IN (SELECT id FROM todos WHERE user_id = ${id})`);
  psql(`DELETE FROM todos WHERE user_id = ${id}`);
  psql(`DELETE FROM daily_notes WHERE user_id = ${id}`);
}

async function main() {
  // Main test user
  ensureUser('test@test.com', 'test1234test', { features: true });
  cleanupTestData('test@test.com');

  // Link test user
  ensureUser('link-test@test.com', 'linktest1234');

  // Admin user (ADMIN_EMAIL=admin@test.com in compose.test.yml)
  ensureUser('admin@test.com', 'admin1234test', { features: true });

  // 2FA test user (isolated for 2FA flow tests)
  ensureUser('2fa@test.com', '2fa1234test');

  // Clean up links between test users
  const emails = ['test@test.com', 'link-test@test.com', 'admin@test.com', '2fa@test.com'];
  const ids = emails.map(e => psql(`SELECT id FROM users WHERE email = '${e}'`)).filter(Boolean);
  if (ids.length > 1) {
    psql(`DELETE FROM account_links WHERE requester_id IN (${ids.join(',')}) OR target_id IN (${ids.join(',')})`);
  }

  // Clean up invite codes from previous test runs
  psql(`DELETE FROM invite_codes WHERE email LIKE '%@test.com' OR email LIKE '%@e2e.local'`);

  // Clean up ephemeral test users from registration tests
  for (const pattern of ['verify-%@test.com', 'invite-%@test.com', 'forgot-%@test.com', 'delete-%@test.com']) {
    psql(`DELETE FROM users WHERE email LIKE '${pattern}'`);
  }

  console.log('All test users ready, test data cleaned up');
}

main().catch((err) => {
  console.error('Setup failed:', err.message);
  process.exit(1);
});
