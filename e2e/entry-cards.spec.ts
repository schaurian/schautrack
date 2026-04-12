import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser } from './fixtures/helpers';

let user: { email: string; password: string; id: string };

test.describe('Entry Cards', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('entry-cards');
  });

  test.afterAll(() => {
    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
  });

  test('entry rows display as cards with macro pills', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // Wait for the form
    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await expect(nameInput).toBeVisible({ timeout: 10000 });

    // Check whether macro inputs are available (protein)
    const macroInputs = page.locator('input[inputmode="numeric"][placeholder="0"]');
    const hasMacros = await macroInputs.first().isVisible({ timeout: 5000 }).catch(() => false);

    // Fill the entry form
    await nameInput.fill('Card Test');
    await page.locator('input[inputmode="tel"]').first().fill('300');

    if (hasMacros) {
      // First numeric input is protein
      await macroInputs.first().fill('20');
    }

    await page.getByRole('button', { name: 'Track' }).click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Find the entry name button (use .first() in case of duplicate entries from re-runs)
    const nameBtn = page.getByRole('button', { name: 'Card Test' }).first();
    await expect(nameBtn).toBeVisible({ timeout: 8000 });

    // Navigate up to the card container:
    //   button(name) -> span.flex-1 -> div.flex(row1) -> div.rounded-[10px](card)
    // MacroPill buttons live in the same rounded-[10px] div as the name
    const card = nameBtn.locator('../../..');
    await expect(card).toBeVisible();

    // The card should contain macro pill buttons (Calories at minimum)
    const caloriePill = card.locator('button').filter({ hasText: /Calories/ });
    const hasCal = await caloriePill.isVisible({ timeout: 3000 }).catch(() => false);

    // Verify either calories pill or protein pill is present
    if (hasMacros) {
      const proteinPill = card.locator('button').filter({ hasText: /Protein/ }).first();
      const hasProt = await proteinPill.isVisible({ timeout: 3000 }).catch(() => false);
      expect(hasCal || hasProt).toBe(true);

      if (hasProt) {
        // Verify the protein value "20" is shown in the pill
        await expect(proteinPill).toContainText('20');
      }
    } else {
      // At least calories pill should be present when calories tracking enabled
      expect(hasCal).toBe(true);
    }

    await ctx.close();
  });
});
