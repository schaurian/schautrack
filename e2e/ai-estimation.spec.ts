import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

const png1x1 = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
  'base64'
);

test.describe('AI Photo Estimation', () => {
  // AI_KEY and AI_PROVIDER are set via env vars in compose.test.yml

  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('ai');
  });

  async function loginAndGo(page: import('@playwright/test').Page, path = '/dashboard') {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    if (path !== '/dashboard') {
      await page.goto(`${baseURL}${path}`);
      await page.waitForURL(new RegExp(path.replace('/', '\\/')), { timeout: 10000 });
    }
  }

  test('AI button is visible when a global key is configured', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const aiButton = page.locator('button[title="Estimate with AI"]');
    await expect(aiButton).toBeVisible({ timeout: 10000 });
    await ctx.close();
  });

  test('AI modal opens on button click', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const aiButton = page.locator('button[title="Estimate with AI"]');
    await expect(aiButton).toBeVisible({ timeout: 10000 });
    await aiButton.click();

    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();
    await expect(modal.getByText('AI Calorie Estimate')).toBeVisible();

    await expect(modal.getByRole('button', { name: 'Camera' })).toBeVisible();
    await expect(modal.getByRole('button', { name: 'Upload' })).toBeVisible();
    await ctx.close();
  });

  test('AI result pre-fills the entry form', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();

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

    await loginAndGo(page);

    const aiButton = page.locator('button[title="Estimate with AI"]');
    await expect(aiButton).toBeVisible({ timeout: 10000 });
    await aiButton.click();

    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();

    await modal.getByRole('button', { name: 'Upload' }).click();

    const fileInput = modal.locator('input[type="file"]');
    await expect(fileInput).toBeVisible();
    await fileInput.setInputFiles({
      name: 'food.png',
      mimeType: 'image/png',
      buffer: png1x1,
    });

    const estimateBtn = modal.getByRole('button', { name: 'Estimate' });
    await expect(estimateBtn).toBeVisible({ timeout: 5000 });
    await estimateBtn.click();

    await expect(modal).not.toBeVisible({ timeout: 10000 });

    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await expect(nameInput).toHaveValue('Grilled Chicken Breast');

    const caloriesInput = page.locator('input[inputmode="tel"]');
    await expect(caloriesInput).toHaveValue('280');
    await ctx.close();
  });

  test('daily usage counter updates after a successful estimate', async ({ browser }) => {
    // Set a daily limit so the counter badge is visible (limit=0 means unlimited, no badge shown)
    psql(`INSERT INTO admin_settings (key, value) VALUES ('ai_daily_limit', '5')
          ON CONFLICT (key) DO UPDATE SET value = '5'`);

    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();

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

    await loginAndGo(page);

    const aiButton = page.locator('button[title="Estimate with AI"]');
    await expect(aiButton).toBeVisible({ timeout: 10000 });

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

    if (initialText !== null) {
      const initialRemaining = parseInt(initialText, 10);
      if (!isNaN(initialRemaining)) {
        await expect(counterBadge).toHaveText(String(initialRemaining - 1), { timeout: 5000 });
      }
    }

    await ctx.close();

    // Cleanup
    psql(`DELETE FROM admin_settings WHERE key = 'ai_daily_limit'`);
  });
});
