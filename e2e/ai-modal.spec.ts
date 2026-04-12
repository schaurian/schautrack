import { test, expect } from '@playwright/test';
import { createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe('AI Photo Modal', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('ai-modal');
  });

  test('AI button opens modal with tabs', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });

    const aiButton = page.locator('button[title="Estimate with AI"]');
    await expect(aiButton).toBeVisible({ timeout: 15000 });

    await aiButton.click();

    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();
    await expect(modal.getByText('AI Calorie Estimate')).toBeVisible();

    await expect(modal.getByRole('button', { name: 'Camera' })).toBeVisible();
    await expect(modal.getByRole('button', { name: 'Upload' })).toBeVisible();

    await modal.getByRole('button', { name: 'Upload' }).click();
    await expect(modal.locator('input[type="file"]')).toBeVisible();

    // Close the modal
    await modal.locator('button.text-destructive').click();
    await expect(modal).not.toBeVisible({ timeout: 3000 });

    await ctx.close();
  });
});
