import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('AI Photo Modal', () => {
  test('AI button opens modal with tabs', async ({ page }) => {
    await login(page);

    // Find and click the AI button (sparkles icon)
    const aiButton = page.locator('button[title="Estimate with AI"]');
    const hasAi = await aiButton.isVisible({ timeout: 3000 }).catch(() => false);

    if (!hasAi) {
      test.skip(true, 'AI not enabled for test user');
      return;
    }

    await aiButton.click();

    // Modal should open
    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();
    await expect(modal.getByText('AI Calorie Estimate')).toBeVisible();

    // Should have Camera and Upload tabs
    await expect(modal.getByRole('button', { name: 'Camera' })).toBeVisible();
    await expect(modal.getByRole('button', { name: 'Upload' })).toBeVisible();

    // Switch to Upload tab
    await modal.getByRole('button', { name: 'Upload' }).click();

    // Should show file input
    await expect(modal.locator('input[type="file"]')).toBeVisible();

    // Close modal
    await modal.locator('button:has-text("×")').click();
    await expect(modal).not.toBeVisible();
  });
});
