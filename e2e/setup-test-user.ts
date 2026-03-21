/**
 * Creates/resets the test user in the E2E test database.
 * Works with both compose.dev.yml and compose.test.yml.
 */
import { execSync } from 'child_process';

const EMAIL = 'test@test.com';
const PASSWORD = 'test1234test';

// Auto-detect which compose stack is running
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

async function main() {
  const hash = execSync(
    `python3 -c "import bcrypt; print(bcrypt.hashpw(b'${PASSWORD}', bcrypt.gensalt(10)).decode())"`,
    { encoding: 'utf-8' }
  ).trim();

  const exists = psql(`SELECT id FROM users WHERE email = '${EMAIL}'`);

  if (exists) {
    psql(`UPDATE users SET password_hash = '${hash}', email_verified = true WHERE email = '${EMAIL}'`);
    console.log(`Test user reset: ${EMAIL} (id: ${exists})`);
  } else {
    psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${EMAIL}', '${hash}', true)`);
    const id = psql(`SELECT id FROM users WHERE email = '${EMAIL}'`);
    console.log(`Test user created: ${EMAIL} (id: ${id})`);
  }

  // Enable all features for test user
  psql(`UPDATE users SET
    macros_enabled = '{"calories": true, "protein": true, "carbs": true, "fat": true, "fiber": true, "sugar": true}',
    macro_goals = '{"calories": 2000, "protein": 150, "carbs": 250, "fat": 65, "fiber": 25, "sugar": 50, "calories_mode": "limit", "protein_mode": "target", "carbs_mode": "limit", "fat_mode": "limit"}',
    todos_enabled = true,
    notes_enabled = true
    WHERE email = '${EMAIL}'`);

  // Clean up leftover test data
  psql(`DELETE FROM calorie_entries WHERE user_id = (SELECT id FROM users WHERE email = '${EMAIL}')`);
  psql(`DELETE FROM weight_entries WHERE user_id = (SELECT id FROM users WHERE email = '${EMAIL}')`);
  psql(`DELETE FROM todo_completions WHERE todo_id IN (SELECT id FROM todos WHERE user_id = (SELECT id FROM users WHERE email = '${EMAIL}'))`);
  psql(`DELETE FROM todos WHERE user_id = (SELECT id FROM users WHERE email = '${EMAIL}')`);
  psql(`DELETE FROM daily_notes WHERE user_id = (SELECT id FROM users WHERE email = '${EMAIL}')`);

  // Create link-test user for account-linking tests
  const linkEmail = 'link-test@test.com';
  const linkHash = execSync(
    `python3 -c "import bcrypt; print(bcrypt.hashpw(b'linktest1234', bcrypt.gensalt(10)).decode())"`,
    { encoding: 'utf-8' }
  ).trim();
  const linkExists = psql(`SELECT id FROM users WHERE email = '${linkEmail}'`);
  if (linkExists) {
    psql(`UPDATE users SET password_hash = '${linkHash}', email_verified = true WHERE email = '${linkEmail}'`);
  } else {
    psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${linkEmail}', '${linkHash}', true)`);
  }
  // Clean up links between test users
  psql(`DELETE FROM account_links WHERE requester_id IN (SELECT id FROM users WHERE email IN ('${EMAIL}', '${linkEmail}')) OR target_id IN (SELECT id FROM users WHERE email IN ('${EMAIL}', '${linkEmail}'))`);

  console.log('Test users ready, all test data cleaned up');
}

main().catch((err) => {
  console.error('Setup failed:', err.message);
  process.exit(1);
});
