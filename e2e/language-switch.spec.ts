import { test, expect } from '@playwright/test';
import { createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

// These tests mutate the user's persisted language preference and share one
// user, so they must run serially.
test.describe.serial('Language selector + autodetect', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('language');
  });

  // Log in (default en context) and land on /settings.
  async function loginAndGoToSettings(page: import('@playwright/test').Page) {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    await page.goto(`${baseURL}/settings`);
    await page.waitForLoadState('domcontentloaded');
  }

  // The language <select> is the only one carrying a German option.
  const langSelect = (page: import('@playwright/test').Page) =>
    page.locator('select').filter({ has: page.locator('option[value="de"]') });

  const htmlLang = (page: import('@playwright/test').Page) =>
    page.evaluate(() => document.documentElement.lang);

  test('explicit language switches the UI live, syncs <html lang>, and persists', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGoToSettings(page);

    const sel = langSelect(page);
    await expect(sel).toBeVisible({ timeout: 10000 });
    // Starts English (Automatic -> en browser).
    await expect(page.getByText('Language', { exact: true })).toBeVisible();

    // Switch to German — label and <html lang> update live.
    await sel.selectOption('de');
    await expect(page.getByText('Sprache', { exact: true })).toBeVisible();
    await expect.poll(() => htmlLang(page)).toBe('de');

    // Let the debounced autosave persist the preference, then reload.
    await page.waitForTimeout(1500);
    await page.reload();
    await page.waitForLoadState('domcontentloaded');

    // Persisted: comes back in German after reload.
    await expect.poll(() => htmlLang(page), { timeout: 10000 }).toBe('de');
    await expect(page.getByText('Sprache', { exact: true })).toBeVisible();
    await expect(langSelect(page)).toHaveValue('de');

    await ctx.close();
  });

  test('Automatic reverts to the browser language', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGoToSettings(page);

    const sel = langSelect(page);
    await expect(sel).toBeVisible({ timeout: 10000 });
    // Persisted German from the previous test.
    await expect.poll(() => htmlLang(page), { timeout: 10000 }).toBe('de');

    // Choose Automatic — reverts to the (en) browser language.
    await sel.selectOption('');
    await expect.poll(() => htmlLang(page)).toBe('en');
    await expect(page.getByText('Language', { exact: true })).toBeVisible();

    await ctx.close();
  });

  test('anonymous visitor gets browser autodetection (German context)', async ({ browser }) => {
    const ctx = await browser.newContext({
      storageState: { cookies: [], origins: [] },
      locale: 'de-DE',
    });
    const page = await ctx.newPage();
    // No login — the detector should pick de from the browser locale.
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await expect.poll(() => htmlLang(page), { timeout: 10000 }).toBe('de');

    await ctx.close();
  });
});
