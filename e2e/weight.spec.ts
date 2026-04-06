import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Weight Tracking', () => {
  test('track and delete weight entry', async ({ page }) => {
    await login(page);

    const weightInput = page.locator('input[aria-label="Weight in kg"], input[aria-label="Weight in lb"]');
    await weightInput.scrollIntoViewIfNeeded({ timeout: 5000 });

    await weightInput.fill('75.5');
    await weightInput.blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 5000 });

    const deleteBtn = page.locator('button[title="Delete weight entry"]');
    await expect(deleteBtn).toBeEnabled({ timeout: 3000 });
    await deleteBtn.click();

    // Weight input should clear or delete button should become disabled
    await expect(page.locator('button[title="Delete weight entry"]')).toBeDisabled({ timeout: 5000 });
  });

  test('weight entry overwrites on same day', async ({ page }) => {
    await login(page);

    const weightInput = page.locator('input[aria-label="Weight in kg"], input[aria-label="Weight in lb"]');
    await weightInput.scrollIntoViewIfNeeded({ timeout: 5000 });

    await weightInput.fill('70');
    await weightInput.blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 5000 });

    await weightInput.fill('75');
    await weightInput.blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 5000 });

    await expect(weightInput).toHaveValue('75', { timeout: 5000 });

    // Cleanup
    await page.locator('button[title="Delete weight entry"]').click();
  });

  test('weight unit label reflects settings selection', async ({ page }) => {
    await login(page);

    // Go to Settings and switch the weight unit
    await page.goto('/settings');
    await page.waitForURL('/settings');
    const weightUnitSelect = page.locator('select').filter({ has: page.locator('option[value="kg"]') });
    await expect(weightUnitSelect).toBeVisible({ timeout: 5000 });
    const currentValue = await weightUnitSelect.inputValue();
    const newValue = currentValue === 'kg' ? 'lb' : 'kg';
    await weightUnitSelect.selectOption(newValue);
    await page.waitForTimeout(1500); // autosave debounce

    // Navigate to dashboard
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    // Verify the weight input label changed
    const expectedLabel = newValue === 'kg' ? 'Weight in kg' : 'Weight in lb';
    await expect(page.locator(`input[aria-label="${expectedLabel}"]`)).toBeVisible({ timeout: 5000 });

    // Restore
    await page.goto('/settings');
    await page.waitForURL('/settings');
    const restoreSelect = page.locator('select').filter({ has: page.locator('option[value="kg"]') });
    await restoreSelect.selectOption(currentValue);
    await page.waitForTimeout(1500);
  });
});
