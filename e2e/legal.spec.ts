import { test, expect } from '@playwright/test';
import { psql } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
const ADMIN_STORAGE = 'e2e/.auth/admin.json';

async function setAdminSetting(browser: import('@playwright/test').Browser, key: string, value: string) {
  const ctx = await browser.newContext({ storageState: ADMIN_STORAGE });
  const csrfRes = await ctx.request.get(`${baseURL}/api/csrf`);
  const { token } = await csrfRes.json();
  await ctx.request.post(`${baseURL}/admin/settings`, {
    headers: { 'X-CSRF-Token': token, 'Content-Type': 'application/json' },
    data: JSON.stringify({ settings: { [key]: value } }),
  });
  await ctx.close();
}

test.describe('Legal Pages', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    // Ensure enable_legal is set in DB (it's not env-controlled)
    psql(`INSERT INTO admin_settings (key, value) VALUES ('enable_legal', 'true') ON CONFLICT (key) DO UPDATE SET value = 'true'`);
  });

  test.afterAll(() => {
    psql(`INSERT INTO admin_settings (key, value) VALUES ('enable_legal', 'true') ON CONFLICT (key) DO UPDATE SET value = 'true'`);
  });

  test('imprint page loads with address content', async ({ browser }) => {
    // Use admin API to ensure cache is invalidated
    await setAdminSetting(browser, 'enable_legal', 'true');

    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await page.goto(`${baseURL}/imprint`);

    await expect(page.getByRole('heading', { name: 'Imprint' })).toBeVisible({ timeout: 10000 });

    const addressImg = page.locator('img[alt="Address"]');
    const emailImg = page.locator('img[alt="Email"]');

    await expect(addressImg).toBeVisible({ timeout: 5000 });
    await expect(emailImg).toBeVisible({ timeout: 5000 });
    await ctx.close();
  });

  test('privacy page loads with policy content', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await page.goto(`${baseURL}/privacy`);

    await expect(page.getByRole('heading', { name: 'Privacy Policy' })).toBeVisible({ timeout: 10000 });
    await ctx.close();
  });

  test('legal pages hidden when disabled', async ({ browser }) => {
    // Disable via admin API (invalidates settings cache)
    await setAdminSetting(browser, 'enable_legal', 'false');

    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();

    // The SVG endpoints should return 404 when legal is disabled
    const addressRes = await page.request.get(`${baseURL}/imprint/address.svg`);
    const emailRes = await page.request.get(`${baseURL}/imprint/email.svg`);

    expect(addressRes.status()).toBe(404);
    expect(emailRes.status()).toBe(404);

    // Restore via admin API
    await setAdminSetting(browser, 'enable_legal', 'true');
    await ctx.close();
  });
});
