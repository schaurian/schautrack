import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { psql } from './fixtures/helpers';

test.describe('Barcode Extended', () => {
  test('barcode button is hidden when admin disables barcode scanning', async ({ page }) => {
    psql(`INSERT INTO admin_settings (key, value) VALUES ('enable_barcode', 'false')
          ON CONFLICT (key) DO UPDATE SET value = 'false'`);

    try {
      await login(page);

      // Reload to pick up the settings change (settings are cached for ~1 min, but a fresh
      // navigation after login fetches fresh data from the API)
      await page.reload();
      await page.waitForLoadState('domcontentloaded');

      const barcodeButton = page.locator('button[title="Scan barcode"]');
      await expect(barcodeButton).not.toBeVisible({ timeout: 5000 });
    } finally {
      psql(`INSERT INTO admin_settings (key, value) VALUES ('enable_barcode', 'true')
            ON CONFLICT (key) DO UPDATE SET value = 'true'`);
    }
  });

  test('barcode result pre-fills the entry form', async ({ page }) => {
    // Ensure barcode is enabled
    psql(`INSERT INTO admin_settings (key, value) VALUES ('enable_barcode', 'true')
          ON CONFLICT (key) DO UPDATE SET value = 'true'`);

    await page.route('**/api/barcode/*', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          name: 'Test Cereal Bar',
          caloriesPer100g: 150,
          macrosPer100g: { protein: 3, carbs: 25, fat: 5 },
          servingSize: null,
          servingQuantity: 100,
        }),
      });
    });

    await login(page);

    const barcodeButton = page.locator('button[title="Scan barcode"]');
    await expect(barcodeButton).toBeVisible({ timeout: 10000 });
    await barcodeButton.click();

    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();
    await expect(modal.getByText('Scan Barcode')).toBeVisible();

    // Switch to Manual tab so we can enter a barcode without a camera
    await modal.getByRole('button', { name: 'Manual' }).click();

    const barcodeInput = modal.locator('input[inputmode="numeric"]');
    await expect(barcodeInput).toBeVisible();
    await barcodeInput.fill('4000417025005');

    await modal.getByRole('button', { name: 'Look up' }).click();

    // Result phase: product name and calories displayed in the modal
    await expect(modal.getByText('Test Cereal Bar')).toBeVisible({ timeout: 10000 });
    await expect(modal.locator('.text-2xl')).toBeVisible();
    await expect(modal.locator('.text-2xl')).toHaveText(/150\s*cal/);

    // Add the entry — modal should close and form should be pre-filled
    await modal.getByRole('button', { name: 'Add Entry' }).click();

    await expect(modal).not.toBeVisible({ timeout: 5000 });

    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await expect(nameInput).toHaveValue('Test Cereal Bar');

    const caloriesInput = page.locator('input[inputmode="tel"]');
    await expect(caloriesInput).toHaveValue('150');
  });
});
