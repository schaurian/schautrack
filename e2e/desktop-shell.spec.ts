import { test, expect } from '@playwright/test';
import { createIsolatedUser, psql } from './fixtures/helpers';

// Desktop used to get an always-open inline entry form while mobile got the FAB
// and a sheet. There is one flow now, so these mirror the mobile-shell specs at
// desktop width: the form is reachable only through the FAB, and the FAB has to
// survive the same toast collision it does on mobile.
const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
const DESKTOP_VIEWPORT = { width: 1440, height: 900 };
let user: { email: string; password: string; id: string };

test.describe('Desktop shell', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('desktop-shell');
    // The quick-add row renders nothing for a user with no saved foods, so seed
    // one — the point of the first test is that the row rides in the sheet.
    psql(`INSERT INTO saved_foods (user_id, name, amount) VALUES (${user.id}, 'Desk Oats', 190)`);
  });

  test.afterAll(() => {
    psql(`DELETE FROM saved_foods WHERE user_id = ${user.id}`);
  });

  async function login(page: import('@playwright/test').Page) {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
  }

  test('the entry form is behind the FAB, not inline on the page', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: DESKTOP_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    const fab = page.getByRole('button', { name: 'Add food' });
    await expect(fab).toBeVisible({ timeout: 15000 });
    // Nothing of the form is on the page until the sheet is opened.
    await expect(page.locator('input[placeholder="Breakfast, snack..."]')).toHaveCount(0);

    await fab.click();
    const dialog = page.getByRole('dialog', { name: 'Add food' });
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('input[placeholder="Breakfast, snack..."]')).toBeVisible();
    // Quick add rides along in the sheet, same as on mobile.
    await expect(dialog.getByTestId('saved-foods-row')).toBeVisible();
    await expect(dialog.getByRole('button', { name: /Desk Oats/ })).toBeVisible();

    await page.keyboard.press('Escape');
    await expect(dialog).not.toBeVisible();
    await ctx.close();
  });

  test('FAB opens the sheet and tracks an entry', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: DESKTOP_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('button', { name: 'Add food' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add food' });
    await expect(dialog).toBeVisible();

    await dialog.locator('input[placeholder="Breakfast, snack..."]').fill('Desktop sheet food');
    await dialog.locator('input[inputmode="tel"]').first().fill('321');
    await dialog.getByRole('button', { name: 'Track' }).click();

    // Tracking closes the sheet and the entry lands in the list without a reload.
    await expect(dialog).not.toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Desktop sheet food')).toBeVisible({ timeout: 10000 });

    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
    await ctx.close();
  });

  test('the undo toast clears the FAB', async ({ browser }) => {
    // Same collision as on mobile: both are fixed bottom-right and the toast
    // paints above the FAB (z-200 vs z-60), so at equal offsets Undo would land
    // on top of the + button.
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: DESKTOP_VIEWPORT });
    const page = await ctx.newPage();
    await login(page);

    await page.getByRole('button', { name: 'Add food' }).click();
    const dialog = page.getByRole('dialog', { name: 'Add food' });
    await dialog.locator('input[placeholder="Breakfast, snack..."]').fill('Desktop undo overlap');
    await dialog.locator('input[inputmode="tel"]').first().fill('123');
    await dialog.getByRole('button', { name: 'Track' }).click();
    await expect(page.getByText('Desktop undo overlap')).toBeVisible({ timeout: 10000 });

    await page.getByRole('button', { name: 'Delete entry' }).first().click();
    const undo = page.getByRole('button', { name: 'Undo' });
    await expect(undo).toBeVisible({ timeout: 10000 });

    const fab = await page.getByRole('button', { name: 'Add food' }).boundingBox();
    const toast = await page.locator('[role="status"] > div').first().boundingBox();
    expect(fab).not.toBeNull();
    expect(toast).not.toBeNull();
    expect(toast!.y + toast!.height).toBeLessThanOrEqual(fab!.y);

    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
    await ctx.close();
  });
});
