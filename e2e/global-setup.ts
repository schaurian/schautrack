import { test as setup, expect } from '@playwright/test';

const AUTH_FILE = 'e2e/.auth/user.json';

setup('authenticate', async ({ page }) => {
  await page.goto('/login');
  await page.waitForLoadState('domcontentloaded');

  await page.getByLabel('Email').fill('test@test.com');
  await page.getByLabel('Password').fill('test1234test');
  await page.getByRole('button', { name: 'Log In' }).click();

  await page.waitForURL('/dashboard', { timeout: 15000 });

  // Save session for all parallel workers to reuse
  await page.context().storageState({ path: AUTH_FILE });
});
