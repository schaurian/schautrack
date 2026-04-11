import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser } from './fixtures/helpers';

let user: { email: string; password: string; id: string };

test.describe('Barcode Extended', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('barcode-ext');
  });

  test.afterAll(() => {
    // Restore barcode setting
    psql(`INSERT INTO admin_settings (key, value) VALUES ('enable_barcode', 'true') ON CONFLICT (key) DO UPDATE SET value = 'true'`);
  });

  test('barcode button is hidden when admin disables barcode scanning', async ({ browser }) => {
    psql(`INSERT INTO admin_settings (key, value) VALUES ('enable_barcode', 'false') ON CONFLICT (key) DO UPDATE SET value = 'false'`);

    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // Barcode button should NOT be visible
    const barcodeButton = page.locator('button[title="Scan barcode"]');
    await expect(barcodeButton).not.toBeVisible({ timeout: 5000 });

    // Restore
    psql(`INSERT INTO admin_settings (key, value) VALUES ('enable_barcode', 'true') ON CONFLICT (key) DO UPDATE SET value = 'true'`);
    await ctx.close();
  });

  test('barcode result pre-fills the entry form', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // Mock the barcode API AFTER page is loaded
    await page.route('**/api/barcode/*', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          name: 'Test Cereal Bar',
          caloriesPer100g: 150,
          macrosPer100g: { protein: 3, carbs: 25, fat: 5 },
          servingSize: '40g',
          servingQuantity: 40,
        }),
      });
    });

    const barcodeButton = page.locator('button[title="Scan barcode"]');
    await expect(barcodeButton).toBeVisible({ timeout: 10000 });
    await barcodeButton.click();

    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible({ timeout: 5000 });

    // Switch to Manual tab
    await modal.getByRole('button', { name: 'Manual' }).click();

    // Enter a barcode in the manual input
    const barcodeInput = modal.getByPlaceholder('Enter barcode number');
    await expect(barcodeInput).toBeVisible({ timeout: 5000 });
    await barcodeInput.fill('5901234123457');
    await modal.getByRole('button', { name: 'Look up' }).click();

    // Wait for result
    await expect(modal.getByText('Test Cereal Bar')).toBeVisible({ timeout: 5000 });

    // Click add/use to pre-fill the form
    const addBtn = modal.getByRole('button', { name: /add|use|track/i }).first();
    if (await addBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
      await addBtn.click();
    }

    // The entry form should be pre-filled
    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await expect(nameInput).toHaveValue('Test Cereal Bar', { timeout: 5000 });

    await ctx.close();
  });
});
