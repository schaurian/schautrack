import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Timeline', () => {
  test('range preset buttons switch the timeline', async ({ page }) => {
    await login(page);

    // Click 7d
    await page.locator('button').filter({ hasText: '7d' }).click();
    await page.waitForTimeout(500);

    // Share card should still be visible
    await expect(page.getByText('You', { exact: true })).toBeVisible();

    // Click 30d
    await page.locator('button').filter({ hasText: '30d' }).click();
    await page.waitForTimeout(500);

    await expect(page.getByText('You', { exact: true })).toBeVisible();
  });

  test('clicking a day dot updates the entry list', async ({ page }) => {
    await login(page);

    // Day dots have aria-label with dates
    const dots = page.locator('button[aria-label*="2026"]');
    const count = await dots.count();

    if (count >= 2) {
      await dots.nth(1).click();

      // Header should show the selected date
      const header = page.locator('h3').filter({ hasText: /2026-\d{2}-\d{2}/ });
      await expect(header).toBeVisible({ timeout: 5000 });
    }
  });

  test('custom date range works', async ({ page }) => {
    await login(page);

    await page.locator('button').filter({ hasText: 'Custom' }).click();

    // Date inputs and Apply button should appear
    const dateInputs = page.locator('input[type="date"]');
    // At least 3 date inputs (entry form + 2 custom range)
    await expect(dateInputs.nth(1)).toBeVisible({ timeout: 3000 });
    await expect(page.getByRole('button', { name: 'Apply' })).toBeVisible();
  });
});
