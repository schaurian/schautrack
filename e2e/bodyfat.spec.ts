import { test, expect } from '@playwright/test';
import { createIsolatedUser, psql } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

const weightInput = 'input[aria-label="Weight in kg"], input[aria-label="Weight in lb"]';
const bodyFatInput = 'input[aria-label="Body fat percentage"]';

test.describe.serial('Body Fat Tracking', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('bodyfat');
    // The field is opt-in. The first test drives the toggle through the UI;
    // the rest start from it already on, so they cover the tracking flow
    // instead of re-testing the setting.
    psql(`UPDATE users SET body_fat_enabled = true WHERE id = ${user.id}`);
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

  test('the settings toggle governs whether the field appears', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    psql(`UPDATE users SET body_fat_enabled = false WHERE id = ${user.id}`);
    await loginAndGo(page);

    await expect(page.locator(bodyFatInput)).toHaveCount(0);

    await page.goto(`${baseURL}/settings`);
    await page.waitForURL(/\/settings/);
    const toggle = page.locator('[data-testid="body-fat-settings-card"] [role="switch"]');
    await expect(toggle).toHaveAttribute('aria-checked', 'false', { timeout: 10000 });
    await toggle.click();
    await expect(toggle).toHaveAttribute('aria-checked', 'true', { timeout: 5000 });

    await page.goto(`${baseURL}/dashboard`);
    await expect(page.locator(bodyFatInput)).toHaveCount(1, { timeout: 10000 });

    await ctx.close();
  });

  test('body fat is disabled until the day has a weight', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    // The weight row pre-fills with the *previous* weight, so accepting a body
    // fat before a weight exists would silently write a stale weight to today.
    //
    // Assertions run against the locator, never a resolved node: the field's
    // React key carries the day's reading, so it remounts on every save and a
    // pinned handle would go stale mid-test.
    const bodyFat = page.locator(bodyFatInput);
    await expect(bodyFat).toBeDisabled({ timeout: 10000 });

    await page.locator(weightInput).fill('80');
    await page.locator(weightInput).blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 5000 });

    await expect(bodyFat).toBeEnabled({ timeout: 5000 });

    await ctx.close();
  });

  test('track, persist and clear a body-fat reading', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const bodyFat = page.locator(bodyFatInput);
    await expect(bodyFat).toBeEnabled({ timeout: 10000 });
    await bodyFat.fill('24.3');
    await bodyFat.blur();
    await expect(page.getByText('Body fat tracked')).toBeVisible({ timeout: 5000 });

    // Reload rather than trusting the in-memory value — this is the assertion
    // that it reached the database.
    await page.reload();
    await expect(page.locator(bodyFatInput)).toHaveValue('24.3', { timeout: 10000 });

    // A weight-only save must not wipe the reading: the upsert leaves body fat
    // alone unless the request explicitly carries the field.
    await page.locator(weightInput).fill('79.5');
    await page.locator(weightInput).blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 5000 });
    await page.reload();
    await expect(page.locator(bodyFatInput)).toHaveValue('24.3', { timeout: 10000 });

    // Emptying the field clears the column rather than being ignored.
    await page.locator(bodyFatInput).fill('');
    await page.locator(bodyFatInput).blur();
    await expect(page.getByText('Body fat removed')).toBeVisible({ timeout: 5000 });
    await page.reload();
    await expect(page.locator(bodyFatInput)).toHaveValue('', { timeout: 10000 });

    await ctx.close();
  });

  test('plan shows composition derived from the reading', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const bodyFat = page.locator(bodyFatInput);
    await expect(bodyFat).toBeEnabled({ timeout: 10000 });
    await bodyFat.fill('25');
    await bodyFat.blur();
    await expect(page.getByText('Body fat tracked')).toBeVisible({ timeout: 5000 });

    await page.goto(`${baseURL}/plan`);
    await page.waitForURL(/\/plan/);

    await expect(page.getByText('Body Fat', { exact: true })).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('25.0')).toBeVisible({ timeout: 5000 });
    // 79.5 kg at 25% -> 59.6 lean / 19.9 fat (rounded to one decimal server-side).
    await expect(page.getByText('59.6 kg lean · 19.9 kg fat')).toBeVisible({ timeout: 5000 });

    await ctx.close();
  });
});
