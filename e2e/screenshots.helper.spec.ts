// Throwaway visual-verification spec — captures redesign screenshots.
// Run: npx playwright test e2e/screenshots.helper.spec.ts --project=chromium
// Not part of CI (delete before merge if it causes noise; harmless otherwise).
import { test } from '@playwright/test';

const SHOTS = process.env.SHOTS_DIR || 'playwright-report/redesign-shots';

async function login(page: import('@playwright/test').Page) {
  await page.goto('/login');
  await page.waitForLoadState('domcontentloaded');
  await page.getByLabel('Email').fill('test@test.com');
  await page.getByLabel('Password').fill('test1234test');
  await page.getByRole('button', { name: 'Log In' }).click();
  await page.waitForURL('/dashboard', { timeout: 15000 });
  await page.waitForTimeout(1200);
}

test.describe('redesign screenshots', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('mobile shots', async ({ browser }) => {
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);
    await page.screenshot({ path: `${SHOTS}/mobile-dashboard.png`, fullPage: false });
    await page.getByRole('button', { name: 'Add food' }).click();
    await page.waitForTimeout(500);
    await page.screenshot({ path: `${SHOTS}/mobile-add-sheet.png` });
    await page.keyboard.press('Escape');
    await page.getByRole('link', { name: 'Settings' }).click();
    await page.waitForURL(/\/settings/);
    await page.waitForTimeout(800);
    await page.screenshot({ path: `${SHOTS}/mobile-settings.png` });
    await page.getByRole('link', { name: 'Plan' }).click();
    await page.waitForURL(/\/plan/);
    await page.waitForTimeout(800);
    await page.screenshot({ path: `${SHOTS}/mobile-plan.png` });
    await ctx.close();
  });

  test('desktop shots', async ({ browser }) => {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);
    await page.screenshot({ path: `${SHOTS}/desktop-dashboard.png` });
    await page.getByRole('link', { name: 'Settings' }).click();
    await page.waitForURL(/\/settings/);
    await page.waitForTimeout(800);
    await page.screenshot({ path: `${SHOTS}/desktop-settings.png` });
    await ctx.close();
  });

  test('login shot', async ({ browser }) => {
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await page.goto('/login');
    await page.waitForLoadState('networkidle');
    await page.screenshot({ path: `${SHOTS}/mobile-login.png` });
    await ctx.close();
  });
});
