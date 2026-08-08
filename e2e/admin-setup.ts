import { test as setup, expect } from '@playwright/test';
import { detectAdminEmail } from './fixtures/helpers';

const AUTH_FILE = 'e2e/.auth/admin.json';

const ADMIN_EMAIL = detectAdminEmail();
const ADMIN_PASSWORD = 'admin1234test';

// The admin user this logs in as is seeded by the `setup` project, which this
// project depends on. The re-seed used to be invoked from HERE, and that was
// #461: `admin-setup` is an ordinary sibling of `2fa`, `auth`, `stepup`,
// `passkey` and `chromium` — they all just declare `dependencies: ['setup']` —
// so a destructive, suite-wide rewrite of every shared user ran concurrently
// with the specs that own those rows. Nothing destructive and global belongs in
// a project that has siblings; see the comment on seedTestUsers() in
// global-setup.ts.
setup('authenticate as admin', async ({ page }) => {
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
