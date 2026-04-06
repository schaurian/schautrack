import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { psql } from './fixtures/helpers';

test.describe('Entry Tracking', () => {
  test('create and delete a calorie entry', async ({ page }) => {
    await login(page);

    // Fill in the entry form
    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Test meal');

    // Try filling cal first, if readonly fill a macro instead
    const calInput = page.locator('input[inputmode="tel"][placeholder="0"]').first();
    const isReadonly = await calInput.getAttribute('readonly');
    if (isReadonly !== null) {
      await page.locator('input[inputmode="numeric"][placeholder="0"]').first().fill('25');
    } else {
      await calInput.fill('500');
    }

    // Submit
    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Wait for entry to appear in the list (no reload needed — SSE updates)
    const entryText = page.getByText('Test meal');
    await entryText.scrollIntoViewIfNeeded({ timeout: 10000 });
    await expect(entryText).toBeVisible({ timeout: 5000 });

    // Delete
    const entryRow = entryText.locator('..').locator('..');
    const deleteBtn = entryRow.locator('button[title="Delete"]');
    if (await deleteBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await deleteBtn.click();
    } else {
      // Try broader search
      const row = page.locator('div').filter({ hasText: 'Test meal' }).last();
      await row.locator('button[title="Delete"]').click();
    }
    await expect(page.getByText('Test meal')).not.toBeVisible({ timeout: 5000 });
  });

  test('math expressions evaluate correctly', async ({ page }) => {
    await login(page);

    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Math test meal');

    const calInput = page.locator('input[inputmode="tel"][placeholder="0"]').first();
    const isReadonly = await calInput.getAttribute('readonly');

    if (isReadonly !== null) {
      // Calories are auto-calculated from macros — skip this test
      test.skip();
      return;
    }

    // Enter a math expression: 200+150 should resolve to 350
    await calInput.fill('200+150');
    await page.locator('form button[type="submit"]').click();

    // The entry should be tracked successfully and show the resolved value 350
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Find the entry row and confirm the resolved calorie value is shown
    const entryRow = page.locator('div').filter({ hasText: 'Math test meal' }).last();
    await entryRow.scrollIntoViewIfNeeded({ timeout: 10000 });
    await expect(entryRow).toBeVisible({ timeout: 5000 });
    await expect(entryRow.getByText('350')).toBeVisible({ timeout: 3000 });

    // Cleanup
    await entryRow.locator('button[title="Delete"]').click();
    await expect(page.getByText('Math test meal')).not.toBeVisible({ timeout: 5000 });
  });

  test('daily total updates after adding entry', async ({ page }) => {
    await login(page);

    // Record the current calorie total shown in the Today panel
    const todaySection = page.locator('section').filter({ has: page.locator('h3', { hasText: 'Today' }) });
    await expect(todaySection).toBeVisible({ timeout: 5000 });

    // Read the current total — it's the large bold number in the Calories chip
    const calChip = todaySection.locator('div').filter({ has: page.locator('div', { hasText: 'Calories' }) }).first();
    const beforeText = await calChip.locator('.text-xl').first().innerText();
    const before = parseInt(beforeText.trim(), 10) || 0;

    // Add a 500-calorie entry
    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Total update test');
    const calInput = page.locator('input[inputmode="tel"][placeholder="0"]').first();
    const isReadonly = await calInput.getAttribute('readonly');
    if (isReadonly !== null) {
      // Calories are auto-calc — skip checking the total update
      test.skip();
      return;
    }
    await calInput.fill('500');
    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Wait for the Today panel to reflect the new total
    await expect(calChip.locator('.text-xl').first()).toContainText(String(before + 500), { timeout: 7000 });

    // Cleanup — delete the entry we just added
    const entryRow = page.locator('div').filter({ hasText: 'Total update test' }).last();
    await entryRow.locator('button[title="Delete"]').click();
    await expect(page.getByText('Total update test')).not.toBeVisible({ timeout: 5000 });
  });

  test('entry rows display as cards with macro pills', async ({ page }) => {
    await login(page);

    // Enable protein macro in settings so the pill is rendered
    await page.goto('/settings');
    await page.waitForURL('/settings');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    const proteinCb = page.getByText('Protein', { exact: true }).locator('..').locator('input[type="checkbox"]');
    const proteinWasChecked = await proteinCb.isChecked();
    if (!proteinWasChecked) {
      await proteinCb.click();
      const saveBtn = page.getByRole('button', { name: 'Save Goals' });
      if (await saveBtn.isVisible({ timeout: 500 }).catch(() => false)) {
        await saveBtn.click();
      } else {
        await page.waitForTimeout(2000);
      }
    }

    // Go to dashboard and add entry with protein=20
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Macro Pill Test');

    const calInput = page.locator('input[inputmode="tel"][placeholder="0"]').first();
    const isReadonly = await calInput.getAttribute('readonly');
    if (isReadonly === null) {
      await calInput.fill('300');
    }
    // Fill protein value (20g)
    const proteinLabel = page.locator('label').filter({ hasText: 'Protein' });
    const hasProteinLabel = await proteinLabel.isVisible({ timeout: 2000 }).catch(() => false);
    if (hasProteinLabel) {
      await proteinLabel.locator('..').locator('input').fill('20');
    }

    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Wait for entry row to appear
    const entryRow = page.locator('div').filter({ hasText: 'Macro Pill Test' }).last();
    await entryRow.scrollIntoViewIfNeeded({ timeout: 10000 });
    await expect(entryRow).toBeVisible({ timeout: 5000 });

    // The entry should contain a macro pill showing "20" (protein value)
    // Pills are rendered as buttons with the value inside a <span>
    await expect(entryRow.locator('button, span').filter({ hasText: /^20$/ }).first()).toBeVisible({ timeout: 5000 });

    // Cleanup
    await entryRow.locator('button[title="Delete"]').click();
    await expect(page.getByText('Macro Pill Test')).not.toBeVisible({ timeout: 5000 });

    // Restore protein checkbox state if it was off
    if (!proteinWasChecked) {
      await page.goto('/settings');
      await page.waitForURL('/settings');
      await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });
      const cb = page.getByText('Protein', { exact: true }).locator('..').locator('input[type="checkbox"]');
      if (await cb.isChecked()) {
        await cb.click();
        const saveBtn = page.getByRole('button', { name: 'Save Goals' });
        if (await saveBtn.isVisible({ timeout: 500 }).catch(() => false)) {
          await saveBtn.click();
        } else {
          await page.waitForTimeout(2000);
        }
      }
    }
  });

  test('dot colors reflect goal progress', async ({ page }) => {
    await login(page);

    // Read the test user's daily goal from the DB, default to 2000 if not set
    const goalStr = psql(`SELECT COALESCE(daily_goal, 2000) FROM users WHERE email = 'test@test.com'`);
    const goal = parseInt(goalStr, 10) || 2000;
    // Add enough calories to go significantly over (goal + 1500 to ensure over_threshold is not needed)
    const overAmount = goal + 500;

    // Get today's date
    const today = new Date().toISOString().split('T')[0];

    // Delete any existing entries for today via psql to start clean
    psql(`DELETE FROM calorie_entries WHERE user_id = (SELECT id FROM users WHERE email = 'test@test.com') AND entry_date = '${today}'`);

    // Navigate to dashboard and add entry over the goal
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    const calInput = page.locator('input[inputmode="tel"][placeholder="0"]').first();
    const isReadonly = await calInput.getAttribute('readonly');
    if (isReadonly !== null) {
      // Can't set calories directly — skip
      test.skip();
      return;
    }

    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Over Goal Test');
    await calInput.fill(String(overAmount));
    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Today's dot should reflect "over" status — it uses bg-warning or bg-destructive classes
    // The dot aria-label contains the status: e.g. "2024-04-06: over" or "2024-04-06: over_threshold"
    const todayDot = page.locator(`button[aria-label^="${today}"]`);
    await expect(todayDot).toBeVisible({ timeout: 5000 });
    const dotLabel = await todayDot.getAttribute('aria-label');
    expect(dotLabel).toMatch(/over/);

    // Cleanup
    psql(`DELETE FROM calorie_entries WHERE user_id = (SELECT id FROM users WHERE email = 'test@test.com') AND entry_date = '${today}'`);
  });

  test('entry date can be changed via date picker', async ({ page }) => {
    await login(page);

    // Compute yesterday's date string
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(today.getDate() - 1);
    const yyyy = yesterday.getFullYear();
    const mm = String(yesterday.getMonth() + 1).padStart(2, '0');
    const dd = String(yesterday.getDate()).padStart(2, '0');
    const yesterdayStr = `${yyyy}-${mm}-${dd}`;

    // Skip if calorie input is read-only (auto-calc mode)
    const calInput = page.locator('input[inputmode="tel"][placeholder="0"]').first();
    const isReadonly = await calInput.getAttribute('readonly');
    if (isReadonly !== null) {
      test.skip();
      return;
    }

    // Change the date in the entry form to yesterday
    const dateInput = page.locator('form input[type="date"]').first();
    await dateInput.fill(yesterdayStr);

    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Yesterday entry');
    await calInput.fill('111');
    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Click the day dot for yesterday to navigate to that date
    const yesterdayDot = page.locator(`button[aria-label^="${yesterdayStr}"]`);
    if (await yesterdayDot.count() > 0) {
      await yesterdayDot.first().click();
    } else {
      // Fallback: click 7d preset so yesterday is within range, then try again
      await page.locator('button').filter({ hasText: '7d' }).click();
      await page.waitForTimeout(500);
      await page.locator(`button[aria-label^="${yesterdayStr}"]`).first().click();
    }

    // The Entries header should now show yesterday's date
    const entriesHeader = page.locator('span').filter({ hasText: yesterdayStr });
    await expect(entriesHeader).toBeVisible({ timeout: 5000 });

    // The entry we created for yesterday should appear
    await expect(page.getByText('Yesterday entry')).toBeVisible({ timeout: 5000 });

    // Cleanup
    const entryRow = page.locator('div').filter({ hasText: 'Yesterday entry' }).last();
    await entryRow.locator('button[title="Delete"]').click();
    await expect(page.getByText('Yesterday entry')).not.toBeVisible({ timeout: 5000 });
  });
});
