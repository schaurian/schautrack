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

    const addressImg = page.locator('img[alt="Postal address of the operator"]');
    const emailImg = page.locator('img[alt="Email address of the operator"]');
    const mstvImg = page.locator('img[alt="Name and postal address of the person responsible for content"]');

    await expect(addressImg).toBeVisible({ timeout: 5000 });
    await expect(emailImg).toBeVisible({ timeout: 5000 });
    await expect(mstvImg).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('Consumer Dispute Resolution')).toBeVisible();
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

  test('registration requires consent when legal pages are enabled', async ({ browser }) => {
    await setAdminSetting(browser, 'enable_legal', 'true');

    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();

    // Server-side enforcement: credentials step without the consent flags is rejected.
    const csrfRes = await page.request.get(`${baseURL}/api/csrf`);
    const { token } = await csrfRes.json();
    const noConsent = await page.request.post(`${baseURL}/api/auth/register`, {
      headers: { 'X-CSRF-Token': token, 'Content-Type': 'application/json' },
      data: JSON.stringify({ step: 'credentials', email: 'e2e-consent@test.local', password: 'test1234test' }),
    });
    expect(noConsent.status()).toBe(400);

    // UI: both checkboxes are shown and gate the submit button.
    await page.goto(`${baseURL}/register`);
    const termsBox = page.getByLabel('Accept the Terms of Service and Privacy Policy');
    const healthBox = page.getByLabel('Consent to health data processing');
    await expect(termsBox).toBeVisible({ timeout: 10000 });
    await expect(healthBox).toBeVisible();

    await page.getByLabel('Email').fill('e2e-consent@test.local');
    await page.getByLabel('Password', { exact: true }).fill('test1234test');
    await page.getByLabel('Confirm Password').fill('test1234test');
    const submit = page.getByRole('button', { name: 'Continue' });
    await expect(submit).toBeDisabled();
    await termsBox.check();
    await expect(submit).toBeDisabled();
    await healthBox.check();
    await expect(submit).toBeEnabled();

    // Complete registration (CAPTCHA_BYPASS accepts any non-empty answer) and
    // verify the consent timestamps were persisted (Art. 7(1) GDPR proof).
    psql(`DELETE FROM users WHERE email = 'e2e-consent@test.local'`);
    await submit.click();
    await page.getByLabel('Captcha').fill('bypass');
    await page.getByRole('button', { name: 'Create Account' }).click();
    await page.waitForURL(/\/(verify-email|dashboard)/, { timeout: 15000 });

    const stamps = psql(
      `SELECT (legal_accepted_at IS NOT NULL) AND (health_consent_at IS NOT NULL) FROM users WHERE email = 'e2e-consent@test.local'`
    );
    expect(stamps).toBe('t');

    psql(`DELETE FROM users WHERE email = 'e2e-consent@test.local'`);
    await ctx.close();
  });
});
