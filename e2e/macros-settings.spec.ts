import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Macro Settings', () => {
  test('toggle macro saves', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 5000 });

    const proteinCheckbox = page.getByText('Protein').locator('..').locator('input[type="checkbox"]');
    const wasChecked = await proteinCheckbox.isChecked();

    // Toggle
    await proteinCheckbox.click();

    // If there's a Save Goals button, click it. Otherwise wait for auto-save.
    const saveBtn = page.getByRole('button', { name: 'Save Goals' });
    if (await saveBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await saveBtn.click();
    } else {
      await page.waitForTimeout(2000);
    }

    // Reload and verify
    await page.reload();
    await page.waitForLoadState('networkidle');
    const afterReload = await page.getByText('Protein').locator('..').locator('input[type="checkbox"]').isChecked();
    expect(afterReload).toBe(!wasChecked);

    // Restore
    await page.getByText('Protein').locator('..').locator('input[type="checkbox"]').click();
    if (await saveBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await saveBtn.click();
    } else {
      await page.waitForTimeout(2000);
    }
  });
});
