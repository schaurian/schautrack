import { test, expect, Browser } from '@playwright/test';
import { createIsolatedUser, loginUser, openAddFood } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
const ADMIN_STORAGE = 'e2e/.auth/admin.json';

let user: { email: string; password: string; id: string };

/**
 * Flip a global admin setting through the admin API rather than with a direct
 * INSERT.
 *
 * The server memoises admin_settings for a minute (database.SettingsCache) and
 * only invalidates that cache on writes it performs itself. A raw psql write
 * therefore takes effect at some unpredictable point up to 60s later — for the
 * disable step that means asserting against a setting that may not be live yet,
 * and for the restore step it means leaving enable_barcode reading `false` for
 * up to a minute after this spec is done, which is exactly what would break the
 * barcode readers that `playwright.config.ts` schedules right after it.
 */
async function setAdminSetting(browser: Browser, key: string, value: string) {
  const ctx = await browser.newContext({ storageState: ADMIN_STORAGE });
  try {
    const csrfRes = await ctx.request.get(`${baseURL}/api/csrf`);
    const { token } = await csrfRes.json();
    const res = await ctx.request.post(`${baseURL}/admin/settings`, {
      headers: { 'X-CSRF-Token': token, 'Content-Type': 'application/json' },
      data: JSON.stringify({ settings: { [key]: value } }),
    });
    expect(res.status(), `failed to set ${key}=${value}`).toBe(200);
  } finally {
    await ctx.close();
  }
}

test.describe('Barcode Extended', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('barcode-ext');
  });

  test.afterAll(async ({ browser }) => {
    // Restore barcode setting
    await setAdminSetting(browser, 'enable_barcode', 'true');
  });

  test('barcode button is hidden when admin disables barcode scanning', async ({ browser }) => {
    await setAdminSetting(browser, 'enable_barcode', 'false');

    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // Barcode button should NOT be visible. It lives in the add-food sheet, so
    // open that first — asserting against a closed sheet would pass either way.
    await openAddFood(page);
    const barcodeButton = page.locator('button[title="Scan barcode"]');
    await expect(barcodeButton).not.toBeVisible({ timeout: 5000 });

    // Restore
    await setAdminSetting(browser, 'enable_barcode', 'true');
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

    await openAddFood(page);
    const barcodeButton = page.locator('button[title="Scan barcode"]');
    await expect(barcodeButton).toBeVisible({ timeout: 10000 });
    await barcodeButton.click();

    // Scoped to the scanner layer: the add-food sheet is a dialog too.
    const modal = page.locator('[data-modal-layer="scanner"]');
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
