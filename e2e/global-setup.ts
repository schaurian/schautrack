import { test as setup, expect } from '@playwright/test';

const AUTH_FILE = 'e2e/.auth/user.json';

setup('authenticate', async ({ page }) => {
  // Navigate to login page
  await page.goto('/login');
  await expect(page.locator('h2')).toHaveText('Log In');

  // Fill in credentials
  await page.getByLabel('Email').fill('test@test.com');
  await page.getByLabel('Password').fill('test1234test');
  await page.getByRole('button', { name: 'Log In' }).click();

  // Wait for redirect to dashboard
  await page.waitForURL('/dashboard');
  await expect(page.locator('body')).toBeVisible();

  // Save signed-in state (cookies + localStorage)
  await page.context().storageState({ path: AUTH_FILE });
});
