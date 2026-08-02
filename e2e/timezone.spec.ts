import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser } from './fixtures/helpers';
import { chooseOption, selectedValue, expectSelectValue } from './fixtures/select';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe('Timezone Handling', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('timezone');
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

  test('change timezone in settings persists after reload', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    await expect(page.getByText('Internationalization')).toBeVisible({ timeout: 10000 });

    const tzSelect = page.locator('#pref-timezone');
    await expect(tzSelect).toBeVisible({ timeout: 5000 });

    const originalTz = await selectedValue(tzSelect);
    const newTz = originalTz === 'America/New_York' ? 'Europe/Berlin' : 'America/New_York';

    await chooseOption(page, tzSelect, newTz);
    await page.waitForTimeout(1500); // autosave

    await page.reload();
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByText('Internationalization')).toBeVisible({ timeout: 10000 });

    const reloaded = page.locator('#pref-timezone');
    await expectSelectValue(reloaded, newTz);

    // Restore
    await chooseOption(page, reloaded, originalTz);
    await page.waitForTimeout(1500);
    await ctx.close();
  });

  test('entry near midnight lands on correct date in user timezone', async ({ browser }) => {
    // Set timezone to UTC+12 (Pacific/Auckland)
    psql(`UPDATE users SET timezone = 'Pacific/Auckland' WHERE id = ${user.id}`);

    // Use a recent date so the dashboard's 30d range still includes it.
    // (Hardcoding caused the test to start failing once the calendar moved
    // past the date.) UTC 11:00 = 23:00 NZST on the same day, so the
    // entry's NZ date matches entry_date.
    const today = new Date();
    today.setUTCDate(today.getUTCDate() - 5);
    const entryDate = today.toISOString().slice(0, 10);
    psql(`INSERT INTO calorie_entries (user_id, entry_date, entry_name, amount, created_at)
          VALUES (${user.id}, '${entryDate}', 'NZ Timezone Test', 100, '${entryDate} 11:00:00+00')`);

    try {
      const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
      const page = await ctx.newPage();
      await loginAndGo(page);

      // Navigate to the entry date via 30d range + dot click (range presets
      // sit behind the "Nd ▾" toggle since the redesign)
      await page.locator('button[aria-expanded="false"]').first().click();
      await page.locator('button').filter({ hasText: '30d' }).click();
      const dot = page.locator(`button[aria-label^="${entryDate}"]`).first();
      await expect(dot).toBeVisible({ timeout: 5000 });
      await dot.click();
      await page.waitForTimeout(500);

      await expect(page.getByText('NZ Timezone Test')).toBeVisible({ timeout: 5000 });

      // Verify it does NOT appear on the next day
      const next = new Date(entryDate);
      next.setUTCDate(next.getUTCDate() + 1);
      const nextDay = next.toISOString().slice(0, 10);
      const nextDot = page.locator(`button[aria-label^="${nextDay}"]`).first();
      if (await nextDot.isVisible({ timeout: 2000 }).catch(() => false)) {
        await nextDot.click();
        await page.waitForTimeout(500);
        await expect(page.getByText('NZ Timezone Test')).not.toBeVisible({ timeout: 3000 });
      }

      await ctx.close();
    } finally {
      psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id} AND entry_name = 'NZ Timezone Test'`);
      psql(`UPDATE users SET timezone = 'UTC' WHERE id = ${user.id}`);
    }
  });

  test('entries display time in viewer timezone', async ({ browser }) => {
    // Set timezone to America/Los_Angeles (PDT = UTC-7)
    psql(`UPDATE users SET timezone = 'America/Los_Angeles' WHERE id = ${user.id}`);

    // Pick a recent date so the dashboard's 30d range still includes it.
    // UTC 20:00 = 13:00 PDT on the same day.
    const today = new Date();
    today.setUTCDate(today.getUTCDate() - 5);
    const entryDate = today.toISOString().slice(0, 10);
    psql(`INSERT INTO calorie_entries (user_id, entry_date, entry_name, amount, created_at)
          VALUES (${user.id}, '${entryDate}', 'LA Time Test', 200, '${entryDate} 20:00:00+00')`);

    try {
      const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
      const page = await ctx.newPage();
      await loginAndGo(page);

      // Navigate to the entry date via 30d range + dot click (range presets
      // sit behind the "Nd ▾" toggle in the Timeline header since the redesign)
      await page.getByRole('button', { name: /^\d+d/, expanded: false }).click();
      await page.getByRole('button', { name: '30d', exact: true }).click();
      await page.waitForTimeout(500);

      const dot = page.locator(`button[aria-label^="${entryDate}"]`).first();
      await expect(dot).toBeVisible({ timeout: 5000 });
      await dot.click();
      await page.waitForTimeout(500);

      // Verify the entry is visible
      const nameBtn = page.getByRole('button', { name: 'LA Time Test', exact: true });
      await expect(nameBtn).toBeVisible({ timeout: 8000 });

      // Check the time display — should show afternoon time in LA timezone.
      // The entry row (EntryList.tsx) renders the time as the span immediately
      // after the span wrapping the name button; neither carries a testid, so
      // anchor on the name button's accessible name and step to its sibling.
      const timeCell = nameBtn.locator('xpath=../following-sibling::span[1]');

      // UTC 20:00 → PDT 13:00. Accept 10:xx to 19:xx (accounts for DST variance)
      await expect(timeCell).toHaveText(/^1[0-9]:\d{2}$/, { timeout: 5000 });

      await ctx.close();
    } finally {
      psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id} AND entry_name = 'LA Time Test'`);
      psql(`UPDATE users SET timezone = 'UTC' WHERE id = ${user.id}`);
    }
  });
});
