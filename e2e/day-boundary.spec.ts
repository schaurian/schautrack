import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser, openAddFood } from './fixtures/helpers';

// A dashboard left open across the user's midnight. When the next refetch
// (window focus, SSE) brings the server's new "today", a user who was on today
// must land on the new today — "Today" pill, and new entries filed under the
// new date — instead of silently staying on yesterday.
//
// The server's clock cannot be mocked from Playwright, so midnight is produced
// the other way round: the user's stored zone is moved from UTC-12 to UTC+14.
// Those are 26 hours apart, so at any real instant the server's "today" for
// the user moves forward by one or two calendar days — exactly what a refetch
// after midnight looks like to the client.
//
// Shot paths come from DAY_BOUNDARY_SHOTS (unset in CI: no screenshots).

const BEFORE_TZ = 'Etc/GMT+12'; // UTC-12 (POSIX sign is inverted)
const AFTER_TZ = 'Etc/GMT-14'; // UTC+14
const ENTRY_NAME = 'After midnight snack';

const dateIn = (tz: string) => new Date().toLocaleDateString('en-CA', { timeZone: tz });

let user: { email: string; password: string; id: string };

test.describe('Day boundary', () => {
  // Both cases drive the same user's timezone; they must not interleave.
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('day-boundary');
    // Skip the welcome tour; its modal would cover the pill and the FAB.
    psql(`UPDATE users SET onboarding_completed_at = NOW() WHERE id = ${user.id}`);
  });

  test.afterAll(() => {
    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
    psql(`UPDATE users SET timezone = NULL WHERE id = ${user.id}`);
  });

  for (const timezoneId of ['Pacific/Auckland', 'America/Los_Angeles']) {
    test(`dashboard follows today across midnight (browser in ${timezoneId})`, async ({ browser }) => {
      psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
      psql(`UPDATE users SET timezone = '${BEFORE_TZ}' WHERE id = ${user.id}`);
      const before = dateIn(BEFORE_TZ);

      const { context, page } = await loginUser(browser, user.email, user.password, { timezoneId });
      await page.goto('/dashboard');
      const pill = page.locator('header').filter({ has: page.locator('input[type="date"]') });
      const dateInput = pill.locator('input[type="date"]');
      await expect(dateInput).toHaveValue(before, { timeout: 15000 });
      await expect(pill).toContainText('Today');
      const shots = process.env.DAY_BOUNDARY_SHOTS;
      const tag = timezoneId.replace('/', '-');
      if (shots) await page.screenshot({ path: `${shots}/${tag}-1-before-midnight.png` });

      // Midnight passes for the user.
      psql(`UPDATE users SET timezone = '${AFTER_TZ}' WHERE id = ${user.id}`);
      const after = dateIn(AFTER_TZ);
      expect(after > before).toBe(true);

      // The user comes back to the tab: react-query refetches on focus once
      // the 5 s staleTime has passed.
      await page.waitForTimeout(5500);
      await page.evaluate(() => window.dispatchEvent(new Event('visibilitychange')));

      await expect(dateInput).toHaveValue(after, { timeout: 10000 });
      await expect(pill).toContainText('Today');

      const dialog = await openAddFood(page);
      await dialog.locator('input[placeholder="Breakfast, snack..."]').fill(ENTRY_NAME);
      await dialog.locator('input[inputmode="tel"]').first().fill('250');
      await dialog.getByRole('button', { name: 'Track' }).click();
      await expect(page.getByRole('button', { name: ENTRY_NAME })).toBeVisible({ timeout: 10000 });
      if (shots) await page.screenshot({ path: `${shots}/${tag}-2-after-midnight.png` });

      expect(psql(`SELECT entry_date FROM calorie_entries WHERE user_id = ${user.id} AND entry_name = '${ENTRY_NAME}'`)).toBe(after);
      await context.close();
    });
  }
});
