import { test as setup, expect } from '@playwright/test';
import { psql, detectAdminEmail } from './fixtures/helpers';

const AUTH_FILE = 'e2e/.auth/admin.json';

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
