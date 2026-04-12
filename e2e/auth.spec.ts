import { test, expect } from '@playwright/test';

test.describe('Authentication', () => {
  test('login redirects to dashboard', async ({ page }) => {
    await page.goto('/login');
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill('test@test.com');
    await page.getByLabel('Password').fill('test1234test');
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL('/dashboard', { timeout: 15000 });
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
    // Login first
    await page.goto('/login');
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill('test@test.com');
    await page.getByLabel('Password').fill('test1234test');
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL('/dashboard', { timeout: 15000 });

    // Now logout
    await page.getByText('Logout').click();
    await expect(page).not.toHaveURL(/\/dashboard/, { timeout: 10000 });
  });
});
