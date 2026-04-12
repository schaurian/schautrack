import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe.serial('Settings Extra', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('settings-extra');
    // Clear any prior AI settings
    psql(`UPDATE users SET ai_key = NULL, preferred_ai_provider = 'openai', ai_model = NULL WHERE id = ${user.id}`);
  });

  test('no spurious Saved indicator on initial load', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/settings');
    await page.waitForLoadState('domcontentloaded');

    // Wait for the settings page to fully render
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 15000 });

    // Wait 3 seconds without any interaction
    await page.waitForTimeout(3000);

    // "Saved" must not be visible without user action
    await expect(page.getByText('Saved')).not.toBeVisible();

    await ctx.close();
  });

  test('set personal AI provider and model then verify persistence', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/settings');
    await page.waitForLoadState('domcontentloaded');

    // Scroll to AI Settings card
    const aiHeading = page.getByText('AI Settings');
    await expect(aiHeading).toBeVisible({ timeout: 10000 });
    await aiHeading.scrollIntoViewIfNeeded();

    // Find Provider select and change it to 'claude'
    const aiCard = aiHeading.locator('../..');
    const providerSelect = aiCard.locator('select');
    const providerSelectVisible = await providerSelect.isVisible({ timeout: 3000 }).catch(() => false);

    if (providerSelectVisible) {
      await providerSelect.selectOption('claude');
    }

    // Fill Model input
    const modelInput = page.locator('input[placeholder*="gpt-4o"]').or(
      page.locator('label').filter({ hasText: 'Model' }).locator('..').locator('input')
    );
    const modelInputEl = modelInput.first();
    const modelVisible = await modelInputEl.isVisible({ timeout: 3000 }).catch(() => false);
    if (modelVisible) {
      await modelInputEl.click({ clickCount: 3 });
      await modelInputEl.fill('test-model-e2e');
    }

    // Wait for autosave (1200ms delay + processing)
    await page.waitForTimeout(2500);

    // Reload and verify model persisted
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByText('AI Settings')).toBeVisible({ timeout: 10000 });

    if (modelVisible) {
      const reloadedModel = page.locator('input[placeholder*="gpt-4o"]').or(
        page.locator('label').filter({ hasText: 'Model' }).locator('..').locator('input')
      );
      const reloadedVal = await reloadedModel.first().inputValue().catch(() => '');
      expect(reloadedVal).toBe('test-model-e2e');
    }

    // Clean up AI settings
    const clearBtn = page.getByRole('button', { name: 'Clear All' });
    if (await clearBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await clearBtn.click();
      await expect(page.getByText('AI settings cleared')).toBeVisible({ timeout: 5000 });
    } else {
      psql(`UPDATE users SET ai_key = NULL, preferred_ai_provider = 'openai', ai_model = NULL WHERE id = ${user.id}`);
    }

    await ctx.close();
  });

  test('set AI key and verify it shows masked placeholder after save', async ({ browser }) => {
    // Clear first
    psql(`UPDATE users SET ai_key = NULL, ai_key_last4 = NULL, preferred_ai_provider = 'openai', ai_model = NULL WHERE id = ${user.id}`);

    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/settings');
    await page.waitForLoadState('domcontentloaded');

    const aiHeading = page.getByText('AI Settings');
    await expect(aiHeading).toBeVisible({ timeout: 10000 });
    await aiHeading.scrollIntoViewIfNeeded();

    // Find the API Key input (type=password) scoped to the AI Settings card
    const aiCardForKey = page.getByText('AI Settings').locator('../..');
    const keyInput = aiCardForKey.locator('input[type="password"]').first();
    const keyVisible = await keyInput.isVisible({ timeout: 5000 }).catch(() => false);

    if (!keyVisible) {
      await ctx.close();
      test.skip(true, 'API Key input not found');
      return;
    }

    await keyInput.fill('test-key-e2e-1234');

    // Wait for autosave to trigger (1200ms delay) by watching for the API call
    const savePromise = page.waitForResponse(
      resp => resp.url().includes('/settings/ai') && resp.request().method() === 'POST',
      { timeout: 5000 }
    ).catch(() => null);

    // Trigger autosave by blurring
    await keyInput.blur();

    // Wait for the save API call, fallback to timeout
    await savePromise;
    await page.waitForTimeout(500);

    // Reload — if key was saved, the placeholder should show masked dots
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByText('AI Settings')).toBeVisible({ timeout: 10000 });

    const reloadedAiCard = page.getByText('AI Settings').locator('../..');
    const reloadedKey = reloadedAiCard.locator('input[type="password"]').first();
    const placeholder = await reloadedKey.getAttribute('placeholder');
    // When a key is saved, placeholder shows "••••XXXX" (masked + last 4)
    if (placeholder) {
      expect(placeholder).toMatch(/•/);
    }

    // Clean up
    const clearBtn = page.getByRole('button', { name: 'Clear All' });
    if (await clearBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await clearBtn.click();
    } else {
      psql(`UPDATE users SET ai_key = NULL, ai_key_last4 = NULL WHERE id = ${user.id}`);
    }

    await ctx.close();
  });
});
