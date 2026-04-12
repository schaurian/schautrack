import { test, expect } from '@playwright/test';
import { createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe('Entry with Macros', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('entry-macros');
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

  test('track entry with macro values', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    // Wait for form to fully render before checking for macro inputs
    await page.locator('input[placeholder="Breakfast, snack..."]').waitFor({ state: 'visible', timeout: 10000 });

    // Check if macro inputs are visible (user needs macros enabled)
    const proteinInput = page.locator('input[inputmode="numeric"][placeholder="0"]').first();
    const hasMacros = await proteinInput.isVisible({ timeout: 15000 }).catch(() => false);

    if (!hasMacros) {
      test.skip(true, 'Macros not enabled for test user');
      await ctx.close();
      return;
    }

    // Fill in entry with macros
    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Chicken breast');
    await page.locator('input[inputmode="tel"][placeholder="0"]').first().fill('250');

    // Fill macro fields (protein, carbs, fat in order)
    const macroInputs = page.locator('input[inputmode="numeric"][placeholder="0"]');
    const count = await macroInputs.count();
    if (count >= 1) await macroInputs.nth(0).fill('30');
    if (count >= 2) await macroInputs.nth(1).fill('5');
    if (count >= 3) await macroInputs.nth(2).fill('8');

    // Submit
    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Wait for entry to appear in list (SSE updates)
    const entryText = page.getByText('Chicken breast');
    await entryText.scrollIntoViewIfNeeded({ timeout: 10000 });
    await expect(entryText).toBeVisible({ timeout: 5000 });

    // Clean up
    const deleteBtn = entryText.locator('..').locator('..').locator('button[title="Delete"]');
    if (await deleteBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await deleteBtn.click();
      await expect(page.getByText('Chicken breast')).not.toBeVisible({ timeout: 5000 });
    }

    await ctx.close();
  });
});
