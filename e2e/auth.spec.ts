import { test, expect } from '@playwright/test';
import { login } from './fixtures/auth';

test.describe('Authentication', () => {
  test('login redirects to dashboard', async ({ page }) => {
    // Use the login helper (reuses cached session, only does fresh login once)
    await login(page);
    await expect(page).toHaveURL(/\/dashboard/);
  });

  test('visiting dashboard when not logged in redirects to login', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/dashboard');
    await expect(page).toHaveURL(/\/login/, { timeout: 10000 });

    await context.close();
  });

  test('logout redirects away from dashboard', async ({ page }) => {
    await login(page);

    // Click Logout
    await page.getByText('Logout').click();
    await expect(page).not.toHaveURL(/\/dashboard/, { timeout: 10000 });
  });
});
