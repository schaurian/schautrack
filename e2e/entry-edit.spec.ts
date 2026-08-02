import { test, expect, type Locator, type Page } from '@playwright/test';
import { createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

/**
 * Scope to a single entry in the entries list.
 *
 * The redesigned EntryList (client/src/pages/Dashboard/EntryList.tsx) renders
 * each entry as a plain <div> without a test id: an upper row holds the name
 * button / time / actions and a lower row holds the macro pills. So the row is
 * the *smallest* element that contains both this entry's name button and its
 * macro pills — match on containment (not nesting depth or CSS classes) and
 * take the deepest hit, since every other match is one of its ancestors.
 *
 * Only ever one pill is in edit mode (an <input>, not a button), so matching
 * "any macro pill button" keeps the row resolvable mid-edit as well.
 */
const MACRO_PILL = /^(Calories|Protein|Carbs|Fat|Fiber|Sugar)\b/;

function entryRow(page: Page, name: string): Locator {
  return page
    .locator('div')
    .filter({ has: page.getByRole('button', { name, exact: true }) })
    .filter({ has: page.getByRole('button', { name: MACRO_PILL }) })
    .last();
}

test.describe('Entry Inline Edit', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('entry-edit');
  });

  async function loginAndGo(page: import('@playwright/test').Page, path = '/dashboard') {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    if (path !== '/dashboard') {
      await page.goto(`${baseURL}${path}`);
      await page.waitForURL(new RegExp(path), { timeout: 10000 });
    }
  }

  async function createEntry(page: any, name: string) {
    await page.locator('input[placeholder="Breakfast, snack..."]').fill(name);
    // Fill protein (always editable, even with auto-calc)
    const macroInputs = page.locator('input[inputmode="numeric"][placeholder="0"]');
    if (await macroInputs.first().isVisible({ timeout: 2000 }).catch(() => false)) {
      await macroInputs.first().fill('20');
    } else {
      await page.locator('input[inputmode="tel"][placeholder="0"]').first().fill('200');
    }
    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });
    await page.waitForTimeout(1000);
  }

  test('edit entry name inline', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);
    await createEntry(page, 'Edit test name');

    // Wait for entry to appear and scroll to it
    const nameBtn = page.getByRole('button', { name: 'Edit test name' });
    await nameBtn.scrollIntoViewIfNeeded({ timeout: 10000 });
    await expect(nameBtn).toBeVisible({ timeout: 5000 });
    await nameBtn.click();

    // Find the edit input that appeared
    const editInput = page.locator('input:focus');
    await expect(editInput).toBeVisible({ timeout: 5000 });

    await editInput.fill('Renamed entry');
    await editInput.press('Enter');

    // Verify
    await expect(page.getByText('Renamed entry')).toBeVisible({ timeout: 5000 });

    // Clean up
    const deleteBtn = entryRow(page, 'Renamed entry').getByRole('button', { name: 'Delete entry' });
    if (await deleteBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await deleteBtn.click();
      await expect(page.getByRole('button', { name: 'Renamed entry', exact: true })).toBeHidden({ timeout: 5000 });
    }

    await ctx.close();
  });

  test('edit entry calorie value inline', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);
    await createEntry(page, 'Cal edit test');

    // Wait for entry to appear in the list
    const entryBtn = page.getByRole('button', { name: 'Cal edit test' });
    await expect(entryBtn).toBeVisible({ timeout: 10000 });
    await entryBtn.scrollIntoViewIfNeeded();

    const row = entryRow(page, 'Cal edit test');

    // The calorie value is a macro pill button labelled "Calories <value> kcal"
    // ("Calories -" while unset). Clicking it swaps the pill for an inline input.
    const caloriePill = row.getByRole('button', { name: /^Calories\b/ });
    await expect(caloriePill).toBeEnabled({ timeout: 5000 });
    await caloriePill.click();

    const editInput = row.getByRole('textbox');
    await expect(editInput).toBeVisible({ timeout: 5000 });
    await editInput.fill('99');
    await editInput.press('Enter');

    await expect(row.getByRole('button', { name: 'Calories 99 kcal' })).toBeVisible({ timeout: 5000 });

    // Clean up
    const deleteBtn = row.getByRole('button', { name: 'Delete entry' });
    if (await deleteBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await deleteBtn.click();
    }

    await ctx.close();
  });
});
