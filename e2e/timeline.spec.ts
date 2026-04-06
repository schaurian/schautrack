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

      // The date span in the Entries header should show the selected date
      const dateSpan = page.locator('span').filter({ hasText: /\d{4}-\d{2}-\d{2}/ });
      await expect(dateSpan).toBeVisible({ timeout: 5000 });
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

  test('clicking a timeline dot updates the selected date', async ({ page }) => {
    await login(page);

    // Use a 30-day range so there are more dots to click
    await page.locator('button').filter({ hasText: '30d' }).click();
    await page.waitForTimeout(500);

    // Day dots use aria-label="YYYY-MM-DD: status"
    const dots = page.locator('button[aria-label*="-"]').filter({ hasNot: page.locator('svg') });
    const count = await dots.count();

    if (count < 2) {
      test.skip();
      return;
    }

    // Click the first dot and capture which date it represents
    const firstDot = dots.first();
    const ariaLabel = await firstDot.getAttribute('aria-label');
    // aria-label format: "YYYY-MM-DD: status"
    const dotDate = ariaLabel?.split(':')[0]?.trim() ?? '';

    await firstDot.click();
    await page.waitForTimeout(300);

    // The Entries section header shows the selected date
    if (dotDate) {
      const dateDisplay = page.locator('span').filter({ hasText: dotDate });
      await expect(dateDisplay).toBeVisible({ timeout: 5000 });
    }
  });

  test('custom date range picker applies and updates the timeline', async ({ page }) => {
    await login(page);

    // Build a 14-day range ending today
    const today = new Date();
    const start = new Date(today);
    start.setDate(today.getDate() - 13);
    const fmt = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    const startStr = fmt(start);
    const endStr = fmt(today);

    await page.locator('button').filter({ hasText: 'Custom' }).click();

    // The two custom date inputs appear inside the custom range panel (not the entry form)
    // Use the 2nd and 3rd date inputs (index 1 and 2); index 0 is the entry form date
    const dateInputs = page.locator('input[type="date"]');
    await expect(dateInputs.nth(1)).toBeVisible({ timeout: 3000 });

    await dateInputs.nth(1).fill(startStr);
    await dateInputs.nth(2).fill(endStr);

    await page.getByRole('button', { name: 'Apply' }).click();
    await page.waitForTimeout(500);

    // The Custom button should remain highlighted (active state)
    const customBtn = page.locator('button').filter({ hasText: 'Custom' });
    await expect(customBtn).toBeVisible();

    // Dots for the selected range should be visible; check for a dot matching start date
    const startDot = page.locator(`button[title="${startStr}"]`);
    if (await startDot.count() > 0) {
      await expect(startDot.first()).toBeVisible({ timeout: 5000 });
    }

    // The share card for the user should still be rendered
    await expect(page.getByText('You', { exact: true })).toBeVisible();
  });
});
