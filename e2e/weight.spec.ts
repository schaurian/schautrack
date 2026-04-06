import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Weight Tracking', () => {
  test('track and delete weight entry', async ({ page }) => {
    await login(page);

    // Weight input is always visible, saves on blur
    const weightInput = page.getByLabel(/Weight in/);
    await weightInput.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(weightInput).toBeVisible();

    // Fill in weight and blur to trigger save
    await weightInput.fill('75.5');
    await weightInput.blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 5000 });

    // Delete button should now be enabled
    const deleteBtn = page.getByTitle('Delete weight entry');
    await expect(deleteBtn).toBeEnabled({ timeout: 3000 });
    await deleteBtn.click();

    // Weight should be cleared
    await expect(weightInput).toHaveValue('', { timeout: 5000 });
  });

  test('weight entry overwrites on same day', async ({ page }) => {
    await login(page);

    const weightInput = page.getByLabel(/Weight in/);
    await weightInput.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(weightInput).toBeVisible();

    // Enter first weight value
    await weightInput.fill('70');
    await weightInput.blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 5000 });

    // Enter a different weight for the same day — should overwrite, not create a second entry
    await weightInput.fill('75');
    await weightInput.blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 5000 });

    // The input should now show 75 (the overwritten value), not 70
    await expect(weightInput).toHaveValue('75', { timeout: 5000 });

    // Only one Delete button should exist in the weight section (not two entries)
    const weightSection = page.locator('div').filter({ has: page.locator('h3', { hasText: 'Weight' }) }).last();
    const deleteButtons = weightSection.locator('button', { hasText: 'Delete' });
    await expect(deleteButtons).toHaveCount(1, { timeout: 3000 });

    // Cleanup
    await deleteButtons.click();
    await expect(weightInput).toHaveValue('', { timeout: 5000 });
  });

  test('weight unit label reflects settings selection', async ({ page }) => {
    await login(page);

    // Read current unit from the weight input aria-label: "Weight in kg" or "Weight in lb"
    const weightInput = page.getByLabel(/Weight in/);
    await weightInput.scrollIntoViewIfNeeded({ timeout: 5000 });
    const ariaLabel = await weightInput.getAttribute('aria-label') ?? '';
    const currentUnit = ariaLabel.includes('kg') ? 'kg' : 'lb';
    const otherUnit = currentUnit === 'kg' ? 'lb' : 'kg';
    const otherUnitValue = otherUnit === 'lb' ? 'lb' : 'kg';

    // Go to Settings and switch the weight unit
    await page.goto('/settings');
    const weightUnitSelect = page.locator('select').filter({ has: page.locator('option[value="kg"]') });
    await expect(weightUnitSelect).toBeVisible({ timeout: 5000 });
    await weightUnitSelect.selectOption(otherUnitValue);

    // Wait for autosave to complete ("Saved" indicator)
    await expect(page.getByText('Saved')).toBeVisible({ timeout: 5000 });

    // Navigate back to the dashboard
    await page.goto('/');

    // The weight input aria-label should now reflect the new unit
    const updatedWeightInput = page.getByLabel(/Weight in/);
    await updatedWeightInput.scrollIntoViewIfNeeded({ timeout: 5000 });
    const updatedLabel = await updatedWeightInput.getAttribute('aria-label') ?? '';
    expect(updatedLabel).toContain(otherUnit);

    // Also confirm the unit abbreviation is shown in the field overlay
    const weightSection = page.locator('div').filter({ has: page.locator('h3', { hasText: 'Weight' }) }).last();
    await expect(weightSection.getByText(otherUnit, { exact: true })).toBeVisible({ timeout: 3000 });

    // Restore original unit
    await page.goto('/settings');
    const restoreSelect = page.locator('select').filter({ has: page.locator('option[value="kg"]') });
    await restoreSelect.selectOption(currentUnit);
    await expect(page.getByText('Saved')).toBeVisible({ timeout: 5000 });
  });
});
