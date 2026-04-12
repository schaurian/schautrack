import { test, expect } from '@playwright/test';
import { createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe.serial('Weight Tracking', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('weight');
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

  test('track and delete weight entry', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const weightInput = page.locator('input[aria-label="Weight in kg"], input[aria-label="Weight in lb"]');
    await weightInput.scrollIntoViewIfNeeded({ timeout: 5000 });

    await weightInput.fill('75.5');
    await weightInput.blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 5000 });

    const deleteBtn = page.locator('button[title="Delete weight entry"]');
    await expect(deleteBtn).toBeEnabled({ timeout: 3000 });
    await deleteBtn.click();

    // Weight input should clear or delete button should become disabled
    await expect(page.locator('button[title="Delete weight entry"]')).toBeDisabled({ timeout: 5000 });

    await ctx.close();
  });

  test('weight entry overwrites on same day', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const weightInput = page.locator('input[aria-label="Weight in kg"], input[aria-label="Weight in lb"]');
    await weightInput.scrollIntoViewIfNeeded({ timeout: 5000 });

    await weightInput.fill('70');
    await weightInput.blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 5000 });
    // Wait for toast to clear before second save to avoid overlap
    await expect(page.getByText('Weight tracked')).not.toBeVisible({ timeout: 8000 });

    await weightInput.fill('75');
    await weightInput.blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 5000 });

    await expect(weightInput).toHaveValue('75', { timeout: 5000 });

    // Cleanup
    await page.locator('button[title="Delete weight entry"]').click();

    await ctx.close();
  });

  test('weight unit label reflects settings selection', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    // Go to Settings and switch the weight unit
    await page.goto(`${baseURL}/settings`);
    await page.waitForURL(/\/settings/);
    const weightUnitSelect = page.locator('select').filter({ has: page.locator('option[value="kg"]') });
    await expect(weightUnitSelect).toBeVisible({ timeout: 5000 });
    const currentValue = await weightUnitSelect.inputValue();
    const newValue = currentValue === 'kg' ? 'lb' : 'kg';
    await weightUnitSelect.selectOption(newValue);
    await page.waitForTimeout(1500); // autosave debounce

    // Navigate to dashboard
    await page.goto(`${baseURL}/dashboard`);
    await page.waitForURL(/\/dashboard/);

    // Verify the weight input label changed
    const expectedLabel = newValue === 'kg' ? 'Weight in kg' : 'Weight in lb';
    await expect(page.locator(`input[aria-label="${expectedLabel}"]`)).toBeVisible({ timeout: 5000 });

    // Restore
    await page.goto(`${baseURL}/settings`);
    await page.waitForURL(/\/settings/);
    const restoreSelect = page.locator('select').filter({ has: page.locator('option[value="kg"]') });
    await restoreSelect.selectOption(currentValue);
    await page.waitForTimeout(1500);

    await ctx.close();
  });
});
