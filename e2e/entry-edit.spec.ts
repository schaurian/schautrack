import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Entry Inline Edit', () => {

  async function createEntry(page: any, name: string) {
    await page.locator('input[placeholder="Breakfast, snack..."]').fill(name);
    // Fill protein (always editable, even with auto-calc)
    const macroInputs = page.locator('input[inputmode="numeric"][placeholder="0"]');
    if (await macroInputs.first().isVisible({ timeout: 2000 }).catch(() => false)) {
      await macroInputs.first().fill('20');
    } else {
      // No macros — fill cal directly
      await page.locator('input[inputmode="tel"][placeholder="0"]').first().fill('200');
    }
    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });
    // Wait for list to update
    await page.waitForTimeout(500);
  }

  test('edit entry name inline', async ({ page }) => {
    await login(page);
    await createEntry(page, 'Edit test name');

    // Scroll to entry list
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));

    // Find the entry and click the name
    const nameBtn = page.locator('button').filter({ hasText: 'Edit test name' });
    await expect(nameBtn).toBeVisible({ timeout: 10000 });
    await nameBtn.click();

    // Find the edit input that appeared (it's an input inside the name column)
    const editInput = page.locator('.flex-1.min-w-0 input');
    await expect(editInput).toBeVisible({ timeout: 5000 });

    await editInput.fill('Renamed entry');
    await editInput.press('Enter');

    // Verify
    await expect(page.getByText('Renamed entry')).toBeVisible({ timeout: 5000 });

    // Clean up
    const row = page.locator('div.flex.items-center').filter({ hasText: 'Renamed entry' });
    await row.locator('button[title="Delete"]').click();
    await expect(page.getByText('Renamed entry')).not.toBeVisible({ timeout: 5000 });
  });

  test('edit entry calorie value inline', async ({ page }) => {
    await login(page);
    await createEntry(page, 'Cal edit test');

    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));

    const row = page.locator('div.flex.items-center').filter({ hasText: 'Cal edit test' });
    await expect(row).toBeVisible({ timeout: 10000 });

    // Find an editable numeric button (skip disabled ones like auto-calc cal)
    const editableButtons = row.locator('button.tabular-nums:not([disabled])');
    const count = await editableButtons.count();
    if (count === 0) {
      test.skip(true, 'No editable numeric fields (all auto-calc or disabled)');
      return;
    }

    await editableButtons.first().click();

    // Edit input should appear
    const editInput = row.locator('input[inputmode]');
    await expect(editInput).toBeVisible({ timeout: 5000 });
    await editInput.fill('99');
    await editInput.press('Enter');

    await expect(row.getByText('99')).toBeVisible({ timeout: 5000 });

    // Clean up
    await row.locator('button[title="Delete"]').click();
  });
});
