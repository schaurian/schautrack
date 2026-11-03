import { test, expect } from '@playwright/test';
import { createIsolatedUser, psql } from './fixtures/helpers';

// Deleting a saved food from the Manage modal shows an Undo toast while the
// modal is still open. A modal Radix dialog sets `pointer-events: none` on
// <body> and the Toaster lives under <body>, so unless the toaster opts back in
// the Undo button is visible but cannot be clicked — the click lands on the
// dialog overlay and closes the modal instead. Only a real browser shows this;
// jsdom does not hit-test.
const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
const DESKTOP_VIEWPORT = { width: 1440, height: 900 };
let user: { email: string; password: string; id: string };

test.describe('Saved food delete Undo', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('saved-food-undo');
  });

  test.afterAll(() => {
    psql(`DELETE FROM saved_foods WHERE user_id = ${user.id}`);
  });

  test('Undo on the delete toast restores the food with the Manage modal open', async ({ browser }) => {
    psql(`DELETE FROM saved_foods WHERE user_id = ${user.id}`);
    // Two foods: with one, deleting it empties the quick-add row, which
    // unmounts the row and the modal with it, and the bug never shows.
    psql(`INSERT INTO saved_foods (user_id, name, amount) VALUES (${user.id}, 'Undo Oats', 190), (${user.id}, 'Keep Rice', 300)`);

    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, viewport: DESKTOP_VIEWPORT });
    const page = await ctx.newPage();
    await page.goto(`${baseURL}/login`);
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });

    await page.getByRole('button', { name: 'Add food' }).click();
    const sheet = page.getByRole('dialog', { name: 'Add food' });
    await sheet.getByRole('button', { name: 'Manage', exact: true }).click();
    const manage = page.locator('[data-modal-layer="saved-foods"]');
    await expect(manage).toBeVisible({ timeout: 10000 });

    await manage.getByText('Undo Oats').waitFor();
    const oatsRow = manage.locator('div.group', { hasText: 'Undo Oats' });
    await oatsRow.getByRole('button', { name: 'Delete saved food' }).click();
    const toast = page.getByText('Deleted Undo Oats');
    await expect(toast).toBeVisible();
    await expect.poll(() => psql(`SELECT count(*) FROM saved_foods WHERE user_id = ${user.id}`)).toBe('1');
    // The precondition for the bug: the modal is still open over the toast.
    await expect(manage).toBeVisible();

    // A real, hit-tested click: Playwright refuses (and the test times out) if
    // another element would receive it.
    // By text, not role: the open modal aria-hides everything outside it.
    await page.locator('[role="status"] button', { hasText: 'Undo' }).click({ timeout: 5000 });

    await expect
      .poll(() => psql(`SELECT count(*) FROM saved_foods WHERE user_id = ${user.id} AND name = 'Undo Oats'`))
      .toBe('1');
    // The modal stayed open: the click went to the toast, not the overlay.
    await expect(manage).toBeVisible();
    await expect(manage.getByText('Undo Oats')).toBeVisible();

    await ctx.close();
  });
});
