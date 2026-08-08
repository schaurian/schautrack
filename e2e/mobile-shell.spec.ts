import { test, expect } from '@playwright/test';
import { createIsolatedUser, psql } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
const MOBILE_VIEWPORT = { width: 390, height: 844 };
let user: { email: string; password: string; id: string };

test.describe('Mobile shell (redesign)', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('mobile-shell');
  });

  async function login(page: import('@playwright/test').Page) {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
  }

  test('bottom tabs navigate', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('link', { name: 'Settings' }).click();
    await expect(page).toHaveURL(/\/settings/, { timeout: 10000 });
    await page.getByRole('link', { name: 'Today' }).click();
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 10000 });
    await ctx.close();
  });

  test('FAB opens sheet and tracks an entry', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('button', { name: 'Add food' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add food' });
    await expect(dialog).toBeVisible();

    await dialog.locator('input[placeholder="Breakfast, snack..."]').fill('Sheet test food');
    await dialog.locator('input[inputmode="tel"]').first().fill('123');
    await dialog.getByRole('button', { name: 'Track' }).click();

    await expect(dialog).not.toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Sheet test food')).toBeVisible({ timeout: 10000 });
    await ctx.close();
  });

  test('tracking a quick-add chip closes the sheet', async ({ browser }) => {
    // Quick add only exists inside the sheet, and tracking a chip
    // completes the task — so the sheet must go down, exactly as it does when
    // the form is submitted.
    psql(`DELETE FROM saved_foods WHERE user_id = ${user.id} AND name = 'Chip Food'`);
    psql(`INSERT INTO saved_foods (user_id, name, amount) VALUES (${user.id}, 'Chip Food', 210)`);

    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('button', { name: 'Add food' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add food' });
    await expect(dialog).toBeVisible();

    const chip = dialog.getByRole('button', { name: /Chip Food/ }).first();
    await expect(chip).toBeVisible({ timeout: 10000 });
    await chip.click();

    await expect(dialog).not.toBeVisible({ timeout: 10000 });
    // and it actually tracked
    await expect(page.getByText('Chip Food').first()).toBeVisible({ timeout: 10000 });

    psql(`DELETE FROM saved_foods WHERE user_id = ${user.id} AND name = 'Chip Food'`);
    await ctx.close();
  });

  test('the barcode scanner opens on top of the add sheet, not behind it', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('button', { name: 'Add food' }).click();
    const sheet = page.getByRole('dialog', { name: 'Add food' });
    await expect(sheet).toBeVisible();

    await sheet.locator('button[title="Scan barcode"]').click();
    const scanner = page.locator('[data-modal-layer="scanner"]');
    await expect(scanner).toBeVisible({ timeout: 10000 });

    // Visible is not enough — it was visible before the fix too, just painted
    // underneath. Hit-testing is no good either: Radix sets pointer-events:none
    // outside an open dialog, so elementFromPoint returns the scanner even when
    // the sheet covers it. Compare the stacking order itself.
    const layering = await page.evaluate(() => {
      const scanner = document.querySelector('[data-modal-layer="scanner"]') as HTMLElement;
      const sheetPanel = document.querySelector('[role="dialog"][aria-label="Add food"]') as HTMLElement;
      return {
        scanner: Number(getComputedStyle(scanner).zIndex),
        sheet: Number(getComputedStyle(sheetPanel.parentElement as HTMLElement).zIndex),
      };
    });
    expect(layering.scanner).toBeGreaterThan(layering.sheet);

    // One Escape closes the scanner and leaves the sheet up, rather than
    // dismissing both through the sheet's document-level listener.
    await page.keyboard.press('Escape');
    await expect(scanner).toBeHidden({ timeout: 5000 });
    await expect(sheet).toBeVisible();

    await ctx.close();
  });

  test('managing quick foods opens on top of the add sheet', async ({ browser }) => {
    psql(`DELETE FROM saved_foods WHERE user_id = ${user.id} AND name = 'Quick Oats'`);
    psql(`INSERT INTO saved_foods (user_id, name, amount) VALUES (${user.id}, 'Quick Oats', 180)`);

    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('button', { name: 'Add food' }).click();
    const sheet = page.getByRole('dialog', { name: 'Add food' });
    await expect(sheet).toBeVisible();

    await sheet.getByRole('button', { name: 'Manage', exact: true }).click();
    const manage = page.locator('[data-modal-layer="saved-foods"]');
    await expect(manage).toBeVisible({ timeout: 10000 });

    const layering = await page.evaluate(() => {
      const modal = document.querySelector('[data-modal-layer="saved-foods"]') as HTMLElement;
      const sheetPanel = document.querySelector('[role="dialog"][aria-label="Add food"]') as HTMLElement;
      return {
        modal: Number(getComputedStyle(modal).zIndex),
        sheet: Number(getComputedStyle(sheetPanel.parentElement as HTMLElement).zIndex),
      };
    });
    expect(layering.modal).toBeGreaterThan(layering.sheet);

    // Escape closes the modal only, leaving the sheet where it was.
    await page.keyboard.press('Escape');
    await expect(manage).toBeHidden({ timeout: 5000 });
    await expect(sheet).toBeVisible();

    psql(`DELETE FROM saved_foods WHERE user_id = ${user.id} AND name = 'Quick Oats'`);
    await ctx.close();
  });

  test('a new quick food is created with its values in one step', async ({ browser }) => {
    psql(`DELETE FROM saved_foods WHERE user_id = ${user.id} AND name = 'Rye Toast'`);
    // The quick-add row (and with it Manage) is not rendered at all for a user
    // with no saved foods, so seed one to get in. Without this the test only
    // passed when a sibling test's food happened to exist at the same time.
    psql(`INSERT INTO saved_foods (user_id, name, amount) VALUES (${user.id}, 'Seed Food', 100)
          ON CONFLICT DO NOTHING`);

    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('button', { name: 'Add food' }).click();
    await page.getByRole('dialog', { name: 'Add food' }).getByRole('button', { name: 'Manage', exact: true }).click();
    const manage = page.locator('[data-modal-layer="saved-foods"]');
    await expect(manage).toBeVisible({ timeout: 10000 });

    // The draft is a saved-food row: same frame, same pills, name focused. Its
    // values are fillable through the very same pills as a saved row's.
    await manage.getByRole('button', { name: /New/ }).click();
    const draft = manage.getByTestId('saved-food-draft');
    await page.keyboard.type('Rye Toast');

    await draft.getByRole('button', { name: /^Calories/ }).click();
    await page.keyboard.type('160');
    await page.keyboard.press('Enter');
    await draft.getByRole('button', { name: /^Protein/ }).click();
    await page.keyboard.type('6');
    await page.keyboard.press('Enter');

    await draft.getByRole('button', { name: 'Add', exact: true }).click();

    await expect(manage.getByText('Rye Toast')).toBeVisible({ timeout: 10000 });

    // Persisted with the values, not just the name.
    await expect.poll(() => psql(
      `SELECT amount || '/' || protein_g FROM saved_foods WHERE user_id = ${user.id} AND name = 'Rye Toast'`,
    ), { timeout: 10000 }).toBe('160/6');

    psql(`DELETE FROM saved_foods WHERE user_id = ${user.id} AND name IN ('Rye Toast', 'Seed Food')`);
    await ctx.close();
  });

  test('sheet closes via Escape and backdrop stays consistent', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('button', { name: 'Add food' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add food' });
    await expect(dialog).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dialog).not.toBeVisible();
    await ctx.close();
  });

  test('the undo toast clears the FAB', async ({ browser }) => {
    // Toast and FAB are both bottom-right fixed; the toast paints above the FAB
    // (z-200 vs z-60), so at equal offsets Undo lands on top of the + button.
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('button', { name: 'Add food' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add food' });
    await dialog.locator('input[placeholder="Breakfast, snack..."]').fill('Undo overlap');
    await dialog.locator('input[inputmode="tel"]').first().fill('123');
    await dialog.getByRole('button', { name: 'Track' }).click();
    await expect(page.getByText('Undo overlap')).toBeVisible({ timeout: 10000 });

    await page.getByRole('button', { name: 'Delete entry' }).first().click();
    // Scope Undo to the toast and match its label exactly. Accessible-name
    // matching is substring-based and case-insensitive, so a bare
    // `{ name: 'Undo' }` on the page also matches the entry button named
    // "Undo overlap" this test just created — and the two genuinely coexist,
    // because handleDelete() shows the toast before the invalidated entry
    // query has refetched the row away. That is a strict-mode violation, not a
    // wait: the locator resolves to 2 elements.
    const toast = page.locator('[role="status"] > div').first();
    const undo = toast.getByRole('button', { name: 'Undo', exact: true });
    await expect(undo).toBeVisible({ timeout: 10000 });

    const fabBox = await page.getByRole('button', { name: 'Add food' }).boundingBox();
    const toastBox = await toast.boundingBox();
    expect(fabBox).not.toBeNull();
    expect(toastBox).not.toBeNull();
    // The toast stack sits fully above the FAB, so Undo stays tappable.
    expect(toastBox!.y + toastBox!.height).toBeLessThanOrEqual(fabBox!.y);

    await ctx.close();
  });

  test('account tab reaches logout in one tap', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: MOBILE_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    // Account is its own tab, so /account is one tap from anywhere — it is not
    // reached by going through Settings.
    await page.getByRole('link', { name: 'Account' }).click();
    await page.waitForURL(/\/account/, { timeout: 10000 });
    await page.getByRole('button', { name: 'Logout' }).click();
    await expect(page).toHaveURL(/\/login/, { timeout: 10000 });
    await ctx.close();
  });
});
