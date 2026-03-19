import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Barcode Lookup', () => {
  test.fixme('manual barcode lookup populates entry form', async ({ page }) => {
    // FIXME: Barcode lookup returns "Lookup failed" — Go backend auth issue on GET /api/barcode
    await login(page);

    // Click the barcode button
    await page.locator('button[title="Scan barcode"]').click();

    // Modal should open
    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();

    // Switch to Manual tab
    await modal.getByRole('button', { name: 'Manual' }).click();

    // Enter barcode and look up
    await modal.locator('input[inputmode="numeric"]').fill('4000417025005');
    await modal.getByRole('button', { name: 'Look up' }).click();

    // Wait for result (external API call)
    await expect(modal.locator('.text-2xl')).toBeVisible({ timeout: 15000 });

    // Add entry
    await modal.getByRole('button', { name: 'Add Entry' }).click();

    // Modal closes, form populated
    await expect(modal).not.toBeVisible();
    await expect(page.locator('input[placeholder="Breakfast, snack..."]')).not.toHaveValue('');
  });
});
