import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('AI Photo Modal', () => {
  test('AI button opens modal with tabs', async ({ page }) => {
    await login(page);
    await page.waitForLoadState('domcontentloaded');

    // AI button only shows if AI is configured
    const aiButton = page.locator('button[title="Estimate with AI"]');
    if (!await aiButton.isVisible({ timeout: 5000 }).catch(() => false)) {
      test.skip(true, 'AI not enabled — no AI_PROVIDER configured');
      return;
    }

    await aiButton.click();

    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();
    await expect(modal.getByText('AI Calorie Estimate')).toBeVisible();

    await expect(modal.getByRole('button', { name: 'Camera' })).toBeVisible();
    await expect(modal.getByRole('button', { name: 'Upload' })).toBeVisible();

    await modal.getByRole('button', { name: 'Upload' }).click();
    await expect(modal.locator('input[type="file"]')).toBeVisible();

    await modal.locator('button.text-destructive').click();
    await expect(modal).not.toBeVisible({ timeout: 3000 });
  });
});
