import { test as setup, expect } from '@playwright/test';
import { psql } from './fixtures/helpers';

const AUTH_FILE = 'e2e/.auth/admin.json';

/**
 * Detect the admin email by checking ADMIN_EMAIL inside the running container.
 * Falls back to admin@test.com (compose.test.yml default).
 */
function detectAdminEmail(): string {
  try {
    const { execSync } = require('child_process');
    const containerName = execSync(
      'docker ps --format "{{.Names}}" | grep -E "schautrack.*web"',
      { encoding: 'utf-8' }
    ).trim().split('\n')[0];
    if (containerName) {
      const email = execSync(
        `docker exec ${containerName} printenv ADMIN_EMAIL`,
        { encoding: 'utf-8' }
      ).trim();
      if (email) return email;
    }
  } catch { /* ignore */ }
  return 'admin@test.com';
}

const ADMIN_EMAIL = detectAdminEmail();
const ADMIN_PASSWORD = 'admin1234test';

setup('authenticate as admin', async ({ page }) => {
  // Ensure the admin user exists in the DB with the correct password
  const { execSync } = require('child_process');
  try {
    execSync(`npx tsx e2e/setup-test-user.ts`, { stdio: 'pipe', timeout: 30000 });
  } catch { /* setup may have already run */ }

  await page.goto('/login');
  await page.waitForLoadState('domcontentloaded');

  await page.getByLabel('Email').fill(ADMIN_EMAIL);
  await page.getByLabel('Password').fill(ADMIN_PASSWORD);
  await page.getByRole('button', { name: 'Log In' }).click();

  await page.waitForURL('/dashboard', { timeout: 15000 });

  // Verify this user actually has admin access
  const meRes = await page.request.get('/api/me');
  const meBody = await meRes.json();
  expect(meBody.isAdmin).toBe(true);

  await page.context().storageState({ path: AUTH_FILE });
});
