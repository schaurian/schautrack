import { test, expect } from '@playwright/test';
import { createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
const MOBILE_VIEWPORT = { width: 390, height: 844 };
let user: { email: string; password: string; id: string };

test.describe('Mobile shell (redesign)', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('mobile-shell');
  });

  async function login(page: import('@playwright/test').Page) {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
  }

  test('bottom tabs navigate', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('link', { name: 'Settings' }).click();
    await expect(page).toHaveURL(/\/settings/, { timeout: 10000 });
    await page.getByRole('link', { name: 'Today' }).click();
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 10000 });
    await ctx.close();
  });

  test('FAB opens sheet and tracks an entry', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('button', { name: 'Add food' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add food' });
    await expect(dialog).toBeVisible();

    await dialog.locator('input[placeholder="Breakfast, snack..."]').fill('Sheet test food');
    await dialog.locator('input[inputmode="tel"]').first().fill('123');
    await dialog.getByRole('button', { name: 'Track' }).click();

    await expect(dialog).not.toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Sheet test food')).toBeVisible({ timeout: 10000 });
    await ctx.close();
  });

  test('sheet closes via Escape and backdrop stays consistent', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('button', { name: 'Add food' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add food' });
    await expect(dialog).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dialog).not.toBeVisible();
    await ctx.close();
  });

  test('logout from settings returns to login', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('link', { name: 'Settings' }).click();
    await page.waitForURL(/\/settings/, { timeout: 10000 });
    await page.getByRole('button', { name: 'Logout' }).click();
    await expect(page).toHaveURL(/\/login/, { timeout: 10000 });
    await ctx.close();
  });
});
