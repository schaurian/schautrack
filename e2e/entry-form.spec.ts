import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Entry Form', () => {
  test('form clears after successful submission', async ({ page }) => {
    await login(page);

    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');

    // Fill name and a macro (works even if cal is auto-calc)
    await nameInput.fill('Clear test');
    const macroInput = page.locator('input[inputmode="numeric"][placeholder="0"]').first();
    if (await macroInput.isVisible().catch(() => false)) {
      await macroInput.fill('10');
    }

    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Form should be cleared
    await expect(nameInput).toHaveValue('');
  });

  test('date picker changes the entry date', async ({ page }) => {
    await login(page);

    const dateInput = page.locator('form input[type="date"]');
    await expect(dateInput).toBeVisible();

    const currentDate = await dateInput.inputValue();
    expect(currentDate).toMatch(/^\d{4}-\d{2}-\d{2}$/);

    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayStr = yesterday.toISOString().split('T')[0];
    await dateInput.fill(yesterdayStr);

    await expect(dateInput).toHaveValue(yesterdayStr);
  });

  test('name input trims whitespace on blur', async ({ page }) => {
    await login(page);

    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await nameInput.fill('  Spaced name  ');
    await nameInput.blur();

    await expect(nameInput).toHaveValue('Spaced name');
  });
});
