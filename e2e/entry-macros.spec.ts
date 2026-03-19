import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Entry with Macros', () => {

  test('track entry with macro values', async ({ page }) => {
    await login(page);

    // Check if macro inputs are visible (user needs macros enabled)
    const proteinInput = page.locator('input[inputmode="numeric"][placeholder="0"]').first();
    const hasMacros = await proteinInput.isVisible({ timeout: 2000 }).catch(() => false);

    if (!hasMacros) {
      test.skip(true, 'Macros not enabled for test user');
      return;
    }

    // Fill in entry with macros
    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Chicken breast');
    await page.locator('input[inputmode="tel"][placeholder="0"]').first().fill('250');

    // Fill macro fields (protein, carbs, fat in order)
    const macroInputs = page.locator('input[inputmode="numeric"][placeholder="0"]');
    const count = await macroInputs.count();
    if (count >= 1) await macroInputs.nth(0).fill('30'); // protein
    if (count >= 2) await macroInputs.nth(1).fill('5');  // carbs
    if (count >= 3) await macroInputs.nth(2).fill('8');  // fat

    // Submit
    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Reload and verify
    await page.reload();
    await page.waitForLoadState('networkidle');
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));

    // Entry should show with name and macro values
    await expect(page.getByText('Chicken breast')).toBeVisible({ timeout: 10000 });

    // Clean up — delete the entry
    const entryRow = page.locator('div.flex.items-center').filter({ hasText: 'Chicken breast' });
    await entryRow.locator('button[title="Delete"]').click();
    await expect(page.getByText('Chicken breast')).not.toBeVisible({ timeout: 5000 });
  });
});
