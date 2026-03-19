import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Entry Tracking', () => {
  test('create and delete a calorie entry', async ({ page }) => {
    await login(page);

    // Fill in the entry form — use protein field since cal may be auto-calc (readonly)
    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Test meal');

    // Try filling cal first, if readonly fill a macro instead
    const calInput = page.locator('input[inputmode="tel"][placeholder="0"]').first();
    const isReadonly = await calInput.getAttribute('readonly');
    if (isReadonly !== null) {
      // Auto-calc enabled — fill protein to create entry
      await page.locator('input[inputmode="numeric"][placeholder="0"]').first().fill('25');
    } else {
      await calInput.fill('500');
    }

    // Submit
    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Reload and verify
    await page.reload();
    await page.waitForLoadState('networkidle');
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));

    await expect(page.getByText('Test meal')).toBeVisible({ timeout: 10000 });

    // Delete
    const entryRow = page.locator('div.flex.items-center').filter({ hasText: 'Test meal' });
    await entryRow.locator('button[title="Delete"]').click();
    await expect(page.getByText('Test meal')).not.toBeVisible({ timeout: 5000 });
  });
});
