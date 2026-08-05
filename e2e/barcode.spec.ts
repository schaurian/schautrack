import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { openAddFood } from './fixtures/helpers';

test.describe('Barcode Lookup', () => {
  test('manual barcode lookup populates entry form', async ({ page }) => {
    await login(page);
    await openAddFood(page);

    // Click the barcode button
    await page.locator('button[title="Scan barcode"]').click();

    // Modal should open. Scoped to the scanner layer: the add-food sheet that
    // holds the barcode button is a dialog too.
    const modal = page.locator('[data-modal-layer="scanner"]');
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
