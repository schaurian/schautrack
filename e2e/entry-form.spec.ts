import { test, expect } from '@playwright/test';
import { createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe('Entry Form', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('entry-form');
  });

  async function loginAndGo(page: import('@playwright/test').Page, path = '/dashboard') {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    if (path !== '/dashboard') {
      await page.goto(`${baseURL}${path}`);
      await page.waitForURL(new RegExp(path), { timeout: 10000 });
    }
  }

  test('form clears after successful submission', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');

    // Fill name and a macro (works even if cal is auto-calc)
    await nameInput.fill('Clear test');
    const macroInput = page.locator('input[inputmode="numeric"][placeholder="0"]').first();
    if (await macroInput.isVisible().catch(() => false)) {
      await macroInput.fill('10');
    }

    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Form should be cleared
    await expect(nameInput).toHaveValue('');

    await ctx.close();
  });

  test('date picker changes the entry date', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const dateInput = page.locator('form input[type="date"]');
    await expect(dateInput).toBeVisible();

    const currentDate = await dateInput.inputValue();
    expect(currentDate).toMatch(/^\d{4}-\d{2}-\d{2}$/);

    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayStr = yesterday.toISOString().split('T')[0];
    await dateInput.fill(yesterdayStr);

    await expect(dateInput).toHaveValue(yesterdayStr);

    await ctx.close();
  });

  test('name input trims whitespace on blur', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await nameInput.fill('  Spaced name  ');
    await nameInput.blur();

    await expect(nameInput).toHaveValue('Spaced name');

    await ctx.close();
  });
});
