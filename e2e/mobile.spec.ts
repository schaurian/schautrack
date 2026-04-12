import { test, expect } from '@playwright/test';
import { createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
const MOBILE_VIEWPORT = { width: 390, height: 844 };
let user: { email: string; password: string; id: string };

test.describe('Mobile Viewport', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('mobile');
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
      await page.waitForURL(new RegExp(path.replace('/', '\\/')), { timeout: 10000 });
    }
  }

  test('dashboard renders on mobile', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await loginAndGo(page);

    await expect(page.getByText('Something went wrong')).not.toBeVisible({ timeout: 3000 });
    await expect(page.locator('input[placeholder="Breakfast, snack..."]')).toBeVisible();
    await ctx.close();
  });

  test('settings page renders on mobile', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    await expect(page.getByText('Something went wrong')).not.toBeVisible({ timeout: 3000 });
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 15000 });
    await ctx.close();
  });

  test('login page renders on mobile', async ({ browser }) => {
    const ctx = await browser.newContext({ viewport: MOBILE_VIEWPORT, storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();

    await page.goto(`${baseURL}/login`);
    await expect(page.getByLabel('Email')).toBeVisible();
    await expect(page.getByLabel('Password')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log In' })).toBeVisible();

    await ctx.close();
  });

  test('calorie input has inputmode="tel"', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const calorieInput = page.locator('input[inputmode="tel"]');
    await expect(calorieInput).toBeVisible({ timeout: 10000 });
    await expect(calorieInput).toHaveAttribute('inputmode', 'tel');
    await ctx.close();
  });

  test('active nav item is visually highlighted', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await loginAndGo(page);

    await page.getByRole('button', { name: 'Toggle menu' }).click();

    const dashboardLink = page.getByRole('link', { name: 'Dashboard' });
    await expect(dashboardLink).toBeVisible();
    await expect(dashboardLink).toHaveClass(/border-\[#0ea5e9\]/);

    await page.getByRole('link', { name: 'Settings' }).click();
    await page.waitForURL(/\/settings/, { timeout: 10000 });

    await page.getByRole('button', { name: 'Toggle menu' }).click();

    const settingsLink = page.getByRole('link', { name: 'Settings' });
    await expect(settingsLink).toBeVisible();
    await expect(settingsLink).toHaveClass(/border-\[#0ea5e9\]/);

    const dashboardLinkInactive = page.getByRole('link', { name: 'Dashboard' });
    await expect(dashboardLinkInactive).not.toHaveClass(/border-\[#0ea5e9\]/);
    await ctx.close();
  });

  test('dashboard has no horizontal scroll on mobile', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await loginAndGo(page);

    await page.waitForLoadState('domcontentloaded');
    await expect(page.locator('input[placeholder="Breakfast, snack..."]')).toBeVisible({ timeout: 10000 });

    const hasHorizontalScroll = await page.evaluate(() => {
      return document.documentElement.scrollWidth > document.documentElement.clientWidth;
    });

    expect(hasHorizontalScroll).toBe(false);
    await ctx.close();
  });

  test('entry form is functional on mobile viewport', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await expect(nameInput).toBeVisible({ timeout: 10000 });

    const calorieInput = page.locator('input[inputmode="tel"]');
    await expect(calorieInput).toBeVisible({ timeout: 5000 });

    await nameInput.fill('Mobile test meal');
    await expect(nameInput).toHaveValue('Mobile test meal');

    await calorieInput.fill('500');
    await expect(calorieInput).toHaveValue('500');

    await nameInput.fill('');
    await calorieInput.fill('');
    await ctx.close();
  });

  test('note editor is visible and accepts input on mobile', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await loginAndGo(page);

    // Enable daily notes via the API (CSRF token required for POST)
    await page.evaluate(async (url) => {
      const csrfRes = await fetch(`${url}/api/csrf`);
      const { token } = await csrfRes.json();
      await fetch(`${url}/api/notes/toggle-enabled`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify({ enabled: true }),
      });
    }, baseURL);

    await page.goto(`${baseURL}/dashboard`);
    await page.waitForURL(/\/dashboard/, { timeout: 10000 });

    const noteTextarea = page.locator('textarea[placeholder="Write a note for this day..."]');
    await expect(noteTextarea).toBeVisible({ timeout: 10000 });

    await noteTextarea.fill('Mobile note test');
    await expect(noteTextarea).toHaveValue('Mobile note test');

    // Clean up — disable notes again so other tests are unaffected
    await page.evaluate(async (url) => {
      const csrfRes = await fetch(`${url}/api/csrf`);
      const { token } = await csrfRes.json();
      await fetch(`${url}/api/notes/toggle-enabled`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify({ enabled: false }),
      });
    }, baseURL);

    await ctx.close();
  });
});
