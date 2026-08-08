import { test, expect, type Locator, type Page } from '@playwright/test';
import { createIsolatedUser, openAddFood } from './fixtures/helpers';

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
    await openAddFood(page);
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

  /**
   * Find a just-created entry by name without knowing which calendar day the
   * server filed it under. Entry dates are resolved in the user's timezone,
   * which need not match the runner's, so probe yesterday/today/tomorrow.
   */
  async function findEntryByName(page: Page, name: string): Promise<{ id: number; date: string }> {
    const now = Date.now();
    for (const offset of [0, -1, 1]) {
      const date = new Date(now + offset * 86400000).toISOString().split('T')[0];
      const res = await page.request.get(`${baseURL}/entries/day?date=${date}`);
      if (!res.ok()) continue;
      const body = await res.json();
      const hit = (body.entries || []).find((e: { name: string | null }) => e.name === name);
      if (hit) return { id: hit.id, date };
    }
    throw new Error(`entry ${name} not found on any nearby date`);
  }

  /**
   * Regression for #303.
   *
   * POST /entries/:id/update decodes into map[string]any and used to coerce
   * every value with fmt.Sprintf("%v", …) before inspecting it, which renders
   * a JSON null as the four-character string "<nil>". The entry-name path did
   * not compare against that sentinel (the amount and macro paths did), so
   * {"name": null} — the documented way to clear the name — renamed the entry
   * to <nil> and the card rendered those four characters to the user.
   *
   * The SPA itself sends "" when the inline editor is emptied, so this state is
   * only reachable from a client that sends a real JSON null; hence the direct
   * request rather than a UI interaction.
   */
  test('clearing a name with an explicit JSON null does not render <nil>', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);
    await createEntry(page, 'Null name test');

    await expect(page.getByRole('button', { name: 'Null name test', exact: true })).toBeVisible({ timeout: 10000 });
    const entry = await findEntryByName(page, 'Null name test');

    const { token } = await (await page.request.get(`${baseURL}/api/csrf`)).json();
    const res = await page.request.post(`${baseURL}/entries/${entry.id}/update`, {
      data: { name: null },
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    });
    expect(res.status()).toBe(200);

    // The server's own view of the entry: the name is cleared, not renamed.
    const updated = await res.json();
    expect(updated.entry.name).toBeNull();

    // And the card the user sees renders the unnamed placeholder, never <nil>.
    // Deliberately not waitForLoadState('networkidle'): the dashboard holds an
    // SSE stream open, so the network never goes idle.
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByRole('button', { name: '—', exact: true }).first()).toBeVisible({ timeout: 10000 });
    await expect(page.getByRole('button', { name: 'Null name test', exact: true })).toHaveCount(0);
    await expect(page.getByText('<nil>')).toHaveCount(0);

    await page.request.post(`${baseURL}/entries/${entry.id}/delete`, {
      headers: { 'X-CSRF-Token': token },
    });
    await ctx.close();
  });

  test('clearing a name through the inline editor does not render <nil>', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);
    await createEntry(page, 'Empty name test');

    const nameBtn = page.getByRole('button', { name: 'Empty name test', exact: true });
    await nameBtn.scrollIntoViewIfNeeded({ timeout: 10000 });
    // Grab the id while the entry is still findable by name — once the name is
    // cleared there is nothing left to look it up by.
    const entry = await findEntryByName(page, 'Empty name test');
    await nameBtn.click();

    const editInput = page.locator('input:focus');
    await expect(editInput).toBeVisible({ timeout: 5000 });
    await editInput.fill('');
    await editInput.press('Enter');

    await expect(page.getByRole('button', { name: 'Empty name test', exact: true })).toHaveCount(0, { timeout: 10000 });
    await expect(page.getByText('<nil>')).toHaveCount(0);

    const { token } = await (await page.request.get(`${baseURL}/api/csrf`)).json();
    await page.request.post(`${baseURL}/entries/${entry.id}/delete`, {
      headers: { 'X-CSRF-Token': token },
    });
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
