import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { psql } from './fixtures/helpers';

const png1x1 = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
  'base64'
);

test.describe('AI Photo Estimation', () => {
  test.beforeAll(() => {
    psql(`INSERT INTO admin_settings (key, value) VALUES ('ai_key', 'test-fake-key')
          ON CONFLICT (key) DO UPDATE SET value = 'test-fake-key'`);
    psql(`INSERT INTO admin_settings (key, value) VALUES ('ai_provider', 'openai')
          ON CONFLICT (key) DO UPDATE SET value = 'openai'`);
  });

  test.afterAll(() => {
    psql(`DELETE FROM admin_settings WHERE key IN ('ai_key', 'ai_provider')`);
  });

  test.skip('AI button is visible when a global key is configured', async ({ page }) => {
    await login(page);

    const aiButton = page.locator('button[title="Estimate with AI"]');
    await expect(aiButton).toBeVisible({ timeout: 10000 });
  });

  test.skip('AI modal opens on button click', async ({ page }) => {
    await login(page);

    const aiButton = page.locator('button[title="Estimate with AI"]');
    await expect(aiButton).toBeVisible({ timeout: 10000 });
    await aiButton.click();

    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();
    await expect(modal.getByText('AI Calorie Estimate')).toBeVisible();

    // Both mode tabs should be present
    await expect(modal.getByRole('button', { name: 'Camera' })).toBeVisible();
    await expect(modal.getByRole('button', { name: 'Upload' })).toBeVisible();
  });

  test.skip('AI result pre-fills the entry form', async ({ page }) => {
    await page.route('**/api/ai/estimate', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          food: 'Grilled Chicken Breast',
          calories: 280,
          macros: { protein: 42, carbs: 0, fat: 12 },
        }),
      });
    });

    await login(page);

    const aiButton = page.locator('button[title="Estimate with AI"]');
    await expect(aiButton).toBeVisible({ timeout: 10000 });
    await aiButton.click();

    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();

    // Switch to Upload mode so we can provide a file without a real camera
    await modal.getByRole('button', { name: 'Upload' }).click();

    const fileInput = modal.locator('input[type="file"]');
    await expect(fileInput).toBeVisible();
    await fileInput.setInputFiles({
      name: 'food.png',
      mimeType: 'image/png',
      buffer: png1x1,
    });

    // After file is selected the image preview and Estimate button appear
    const estimateBtn = modal.getByRole('button', { name: 'Estimate' });
    await expect(estimateBtn).toBeVisible({ timeout: 5000 });
    await estimateBtn.click();

    // Modal should close and entry form should be pre-filled
    await expect(modal).not.toBeVisible({ timeout: 10000 });

    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await expect(nameInput).toHaveValue('Grilled Chicken Breast');

    // Calories input (inputMode="tel", placeholder="0")
    const caloriesInput = page.locator('input[inputmode="tel"]');
    await expect(caloriesInput).toHaveValue('280');
  });

  test.skip('daily usage counter updates after a successful estimate', async ({ page }) => {
    // Set a limit so the counter is shown
    psql(`INSERT INTO admin_settings (key, value) VALUES ('ai_daily_limit', '5')
          ON CONFLICT (key) DO UPDATE SET value = '5'`);

    await page.route('**/api/ai/estimate', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          food: 'Apple',
          calories: 95,
          macros: {},
        }),
      });
    });

    await login(page);

    const aiButton = page.locator('button[title="Estimate with AI"]');
    await expect(aiButton).toBeVisible({ timeout: 10000 });

    // The counter badge inside the AI button shows remaining uses
    // It only renders when limit > 0, so we capture the initial value
    const counterBadge = aiButton.locator('span');
    const initialText = await counterBadge.textContent({ timeout: 5000 }).catch(() => null);

    await aiButton.click();

    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();

    await modal.getByRole('button', { name: 'Upload' }).click();
    const fileInput = modal.locator('input[type="file"]');
    await fileInput.setInputFiles({
      name: 'food.png',
      mimeType: 'image/png',
      buffer: png1x1,
    });

    const estimateBtn = modal.getByRole('button', { name: 'Estimate' });
    await expect(estimateBtn).toBeVisible({ timeout: 5000 });
    await estimateBtn.click();

    await expect(modal).not.toBeVisible({ timeout: 10000 });

    // After a successful estimate the remaining counter should be one less than before
    if (initialText !== null) {
      const initialRemaining = parseInt(initialText, 10);
      if (!isNaN(initialRemaining)) {
        await expect(counterBadge).toHaveText(String(initialRemaining - 1), { timeout: 5000 });
      }
    }

    // Cleanup
    psql(`DELETE FROM admin_settings WHERE key = 'ai_daily_limit'`);
  });
});
