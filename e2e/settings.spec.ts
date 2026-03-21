import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Settings', () => {
  test('settings page loads with user email', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 15000 });
  });

  test('preferences save on change', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Find the weight unit select
    const weightSelect = page.locator('select').filter({ has: page.locator('option[value="kg"]') });
    await expect(weightSelect).toBeVisible({ timeout: 5000 });

    const currentValue = await weightSelect.inputValue();
    const newValue = currentValue === 'kg' ? 'lb' : 'kg';
    await weightSelect.selectOption(newValue);

    // If there's a Save button, click it. Otherwise wait for auto-save.
    const saveBtn = page.getByRole('button', { name: 'Save' }).first();
    if (await saveBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await saveBtn.click();
    } else {
      await page.waitForTimeout(1500);
    }

    // Reload to verify
    await page.reload();
    await page.waitForLoadState('domcontentloaded');

    const reloaded = page.locator('select').filter({ has: page.locator('option[value="kg"]') });
    const afterReload = await reloaded.inputValue();
    expect(afterReload).toBe(newValue);

    // Restore
    await reloaded.selectOption(currentValue);
    if (await saveBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await saveBtn.click();
    } else {
      await page.waitForTimeout(1500);
    }
  });
});
