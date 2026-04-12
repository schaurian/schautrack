import { test, expect } from '@playwright/test';
import { createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe('Entry Inline Edit', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('entry-edit');
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

  async function createEntry(page: any, name: string) {
    await page.locator('input[placeholder="Breakfast, snack..."]').fill(name);
    // Fill protein (always editable, even with auto-calc)
    const macroInputs = page.locator('input[inputmode="numeric"][placeholder="0"]');
    if (await macroInputs.first().isVisible({ timeout: 2000 }).catch(() => false)) {
      await macroInputs.first().fill('20');
    } else {
      await page.locator('input[inputmode="tel"][placeholder="0"]').first().fill('200');
    }
    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });
    await page.waitForTimeout(1000);
  }

  test('edit entry name inline', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);
    await createEntry(page, 'Edit test name');

    // Wait for entry to appear and scroll to it
    const nameBtn = page.getByRole('button', { name: 'Edit test name' });
    await nameBtn.scrollIntoViewIfNeeded({ timeout: 10000 });
    await expect(nameBtn).toBeVisible({ timeout: 5000 });
    await nameBtn.click();

    // Find the edit input that appeared
    const editInput = page.locator('input:focus');
    await expect(editInput).toBeVisible({ timeout: 5000 });

    await editInput.fill('Renamed entry');
    await editInput.press('Enter');

    // Verify
    await expect(page.getByText('Renamed entry')).toBeVisible({ timeout: 5000 });

    // Clean up
    const deleteBtn = page.getByText('Renamed entry').locator('..').locator('..').locator('button[title="Delete"]');
    if (await deleteBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await deleteBtn.click();
    }

    await ctx.close();
  });

  test('edit entry calorie value inline', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);
    await createEntry(page, 'Cal edit test');

    // Wait for entry to appear in the list
    const entryBtn = page.getByRole('button', { name: 'Cal edit test' });
    await expect(entryBtn).toBeVisible({ timeout: 10000 });
    await entryBtn.scrollIntoViewIfNeeded();

    // The outer entry container is 3 levels up from the button:
    // button → span → row-1-div → outer-entry-div
    const row = entryBtn.locator('..').locator('..').locator('..');

    // Find an editable numeric button (calorie or macro value pill)
    const editableButtons = row.locator('button.tabular-nums:not([disabled])');
    await expect(editableButtons.first()).toBeVisible({ timeout: 5000 });
    await editableButtons.first().click();

    const editInput = row.locator('input[inputmode]');
    await expect(editInput).toBeVisible({ timeout: 5000 });
    await editInput.fill('99');
    await editInput.press('Enter');

    await expect(row.locator('.tabular-nums').filter({ hasText: '99' }).first()).toBeVisible({ timeout: 5000 });

    // Clean up
    const deleteBtn = row.locator('button[title="Delete"]');
    if (await deleteBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await deleteBtn.click();
    }

    await ctx.close();
  });
});
