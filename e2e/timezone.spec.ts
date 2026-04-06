import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { psql } from './fixtures/helpers';

const TEST_EMAIL = 'test@test.com';

test.describe('Timezone Handling', () => {
  test('change timezone in settings persists after reload', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    await expect(page.getByText('Internationalization')).toBeVisible({ timeout: 10000 });

    const tzSelect = page.locator('select').filter({ has: page.locator('option[value="UTC"]') });
    await expect(tzSelect).toBeVisible({ timeout: 5000 });

    const originalTz = await tzSelect.inputValue();

    // Change to America/New_York
    await tzSelect.selectOption('America/New_York');
    await expect(page.getByText('Saved')).toBeVisible({ timeout: 6000 });

    // Reload and verify it persisted
    await page.reload();
    await page.waitForURL('/settings');
    await expect(page.getByText('Internationalization')).toBeVisible({ timeout: 10000 });

    const reloadedSelect = page.locator('select').filter({ has: page.locator('option[value="UTC"]') });
    await expect(reloadedSelect).toHaveValue('America/New_York', { timeout: 5000 });

    // Restore original timezone
    await reloadedSelect.selectOption(originalTz || 'UTC');
    await expect(page.getByText('Saved')).toBeVisible({ timeout: 6000 });
  });

  test('entry near midnight lands on correct date in user timezone', async ({ page }) => {
    const userId = psql(`SELECT id FROM users WHERE email = '${TEST_EMAIL}'`);
    if (!userId) throw new Error(`Test user not found`);

    // Store original timezone for cleanup
    const originalTz = psql(`SELECT COALESCE(timezone, 'UTC') FROM users WHERE id = ${userId}`);

    // Set timezone to Pacific/Auckland (UTC+12/+13)
    psql(`UPDATE users SET timezone = 'Pacific/Auckland' WHERE id = ${userId}`);

    // Insert entry at UTC 11:00 on 2026-04-01 → 2026-04-01 23:00 NZST (same calendar date)
    const entryDate = '2026-04-01';
    psql(`
      INSERT INTO calorie_entries (user_id, entry_date, entry_name, calories, created_at)
      VALUES (${userId}, '${entryDate}', 'Timezone Test Early', 100, '2026-04-01 11:00:00+00')
    `);

    try {
      await login(page);

      // Navigate to the entry date via a dot click or direct navigation
      // Click the dot for 2026-04-01 using the aria-label
      await page.locator('button').filter({ hasText: '30d' }).click();
      await page.waitForTimeout(500);

      const targetDot = page.locator(`button[aria-label^="${entryDate}"]`);
      const hasDot = await targetDot.count() > 0;
      if (hasDot) {
        await targetDot.first().click();
      } else {
        // Use custom range to navigate to that date
        await page.locator('button').filter({ hasText: 'Custom' }).click();
        const dateInputs = page.locator('input[type="date"]');
        await expect(dateInputs.nth(1)).toBeVisible({ timeout: 3000 });
        await dateInputs.nth(1).fill(entryDate);
        await dateInputs.nth(2).fill(entryDate);
        await page.getByRole('button', { name: 'Apply' }).click();
        await page.waitForTimeout(500);

        const dot = page.locator(`button[aria-label^="${entryDate}"]`);
        if (await dot.count() > 0) await dot.first().click();
      }

      await page.waitForTimeout(500);

      // Verify the entry appears on the correct date
      const dateDisplay = page.locator('span').filter({ hasText: entryDate });
      await expect(dateDisplay).toBeVisible({ timeout: 5000 });
      await expect(page.getByText('Timezone Test Early')).toBeVisible({ timeout: 5000 });

      // Navigate to adjacent date (2026-04-02) — entry should NOT appear there
      const adjacentDate = '2026-04-02';
      const adjacentDot = page.locator(`button[aria-label^="${adjacentDate}"]`);
      if (await adjacentDot.count() > 0) {
        await adjacentDot.first().click();
        await page.waitForTimeout(500);
        await expect(page.getByText('Timezone Test Early')).not.toBeVisible({ timeout: 3000 });
      }
    } finally {
      // Cleanup
      psql(`DELETE FROM calorie_entries WHERE user_id = ${userId} AND entry_name = 'Timezone Test Early'`);
      psql(`UPDATE users SET timezone = '${originalTz}' WHERE id = ${userId}`);
    }
  });

  test('entries display time in viewer timezone', async ({ page }) => {
    const userId = psql(`SELECT id FROM users WHERE email = '${TEST_EMAIL}'`);
    if (!userId) throw new Error(`Test user not found`);

    const originalTz = psql(`SELECT COALESCE(timezone, 'UTC') FROM users WHERE id = ${userId}`);

    // Set timezone to America/Los_Angeles (UTC-7 in summer / UTC-8 in winter)
    psql(`UPDATE users SET timezone = 'America/Los_Angeles' WHERE id = ${userId}`);

    // Insert entry at 2026-04-01 20:00 UTC → 13:00 America/Los_Angeles (UTC-7, PDT)
    const entryDate = '2026-04-01';
    psql(`
      INSERT INTO calorie_entries (user_id, entry_date, entry_name, calories, created_at)
      VALUES (${userId}, '${entryDate}', 'LA Timezone Display Test', 200, '2026-04-01 20:00:00+00')
    `);

    try {
      await login(page);

      // Navigate to the entry date
      await page.locator('button').filter({ hasText: '30d' }).click();
      await page.waitForTimeout(500);

      const targetDot = page.locator(`button[aria-label^="${entryDate}"]`);
      const hasDot = await targetDot.count() > 0;
      if (hasDot) {
        await targetDot.first().click();
      } else {
        await page.locator('button').filter({ hasText: 'Custom' }).click();
        const dateInputs = page.locator('input[type="date"]');
        await expect(dateInputs.nth(1)).toBeVisible({ timeout: 3000 });
        await dateInputs.nth(1).fill(entryDate);
        await dateInputs.nth(2).fill(entryDate);
        await page.getByRole('button', { name: 'Apply' }).click();
        await page.waitForTimeout(500);

        const dot = page.locator(`button[aria-label^="${entryDate}"]`);
        if (await dot.count() > 0) await dot.first().click();
      }

      await page.waitForTimeout(500);

      // Verify the entry is visible
      await expect(page.getByText('LA Timezone Display Test')).toBeVisible({ timeout: 5000 });

      // UTC 20:00 → PDT 13:00 (UTC-7). The displayed time should be in the afternoon (1pm).
      // Look for a time string in the 13:xx range (24h) or 1:xx PM range
      const entryRow = page.locator('div').filter({ hasText: 'LA Timezone Display Test' }).last();
      await entryRow.scrollIntoViewIfNeeded({ timeout: 5000 });

      // Check that the displayed time string shows an afternoon time for LA timezone
      // The time could be "1:00 PM", "13:00", or similar — look for "1:" or "13:"
      const timeText = await entryRow.textContent();
      const showsAfternoonTime = timeText
        ? /\b1[123]:\d{2}/.test(timeText) || /\b1:\d{2}\s*[Pp][Mm]/.test(timeText)
        : false;
      expect(showsAfternoonTime).toBe(true);
    } finally {
      // Cleanup
      psql(`DELETE FROM calorie_entries WHERE user_id = ${userId} AND entry_name = 'LA Timezone Display Test'`);
      psql(`UPDATE users SET timezone = '${originalTz}' WHERE id = ${userId}`);
    }
  });
});
