/**
 * Run before E2E tests to ensure test user exists with correct password.
 * Usage: npx tsx e2e/setup-test-user.ts
 */
import { execSync } from 'child_process';

const EMAIL = 'test@test.com';
const PASSWORD = 'test1234test';
const DB_CONTAINER = 'schautrack-db-1';
const DB_USER = process.env.POSTGRES_USER || 'schautrack';
const DB_NAME = process.env.POSTGRES_DB || 'schautrack';

function psql(sql: string): string {
  return execSync(
    `docker exec ${DB_CONTAINER} psql -U ${DB_USER} -d ${DB_NAME} -tAc "${sql.replace(/"/g, '\\"')}"`,
    { encoding: 'utf-8' }
  ).trim();
}

async function main() {
  // Generate bcrypt hash
  const hash = execSync(
    `python3 -c "import bcrypt; print(bcrypt.hashpw(b'${PASSWORD}', bcrypt.gensalt(10)).decode())"`,
    { encoding: 'utf-8' }
  ).trim();

  // Check if user exists
  const exists = psql(`SELECT id FROM users WHERE email = '${EMAIL}'`);

  if (exists) {
    // Reset password and ensure email is verified
    psql(`UPDATE users SET password_hash = '${hash}', email_verified = true WHERE email = '${EMAIL}'`);
    console.log(`Test user reset: ${EMAIL} (id: ${exists})`);
  } else {
    // Create user
    psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${EMAIL}', '${hash}', true)`);
    const id = psql(`SELECT id FROM users WHERE email = '${EMAIL}'`);
    console.log(`Test user created: ${EMAIL} (id: ${id})`);
  }

  // Ensure macros and todos are enabled
  psql(`UPDATE users SET
    macros_enabled = '{"calories": true, "protein": true, "carbs": true, "fat": true, "fiber": true, "sugar": true}',
    macro_goals = '{"calories": 2000, "protein": 150, "carbs": 250, "fat": 65, "fiber": 25, "sugar": 50, "calories_mode": "limit", "protein_mode": "target", "carbs_mode": "limit", "fat_mode": "limit"}',
    todos_enabled = true
    WHERE email = '${EMAIL}'`);

  // Clean up leftover test entries
  psql(`DELETE FROM calorie_entries WHERE user_id = (SELECT id FROM users WHERE email = '${EMAIL}')`);
  psql(`DELETE FROM weight_entries WHERE user_id = (SELECT id FROM users WHERE email = '${EMAIL}')`);

  console.log('Test user ready, entries cleaned up');
}

main().catch((err) => {
  console.error('Setup failed:', err.message);
  process.exit(1);
});
