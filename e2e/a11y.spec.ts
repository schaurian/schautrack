import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { psql, createIsolatedUser, loginUser, openAddFood } from './fixtures/helpers';

/**
 * Accessibility regressions: an axe pass over the main screens, plus the
 * keyboard/focus behaviour axe cannot see (where focus goes after a delete, the
 * add-food dialog's focus handling, the date pill, inline-edit feedback).
 *
 * Rules switched off below are known, open findings rather than accepted ones —
 * each has a reason next to it. Everything else must stay at zero.
 */

const TODAY = new Date().toLocaleDateString('en-CA', { timeZone: 'UTC' });

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'];

// Known, open findings that live only inside the timeline's share cards:
// nested-interactive / label-content-name-mismatch — the card is a
// role="button" that contains the day-dot and label-edit buttons; untangling
// it is a structural change of that card. The dots are reachable and labeled.
// They are waived for the share card only. The rest of the page is checked
// with every rule, and the card itself with every rule but these.
// (target-size used to be waived here too, until the dots became 44px.)
const SHARE_CARD = '[data-testid="share-card"]';
const SHARE_CARD_WAIVED = ['nested-interactive', 'label-content-name-mismatch'];

// Settings and Plan are built from cards headed <h3>, with no h1/h2 above them.
// Adding only an h1 trades this finding for heading-order; the real fix is
// moving every card heading to h2, a sweep across ~20 files.
const NO_H1_YET = ['page-has-heading-one'];

async function expectNoViolations(page: Page, extraDisabled: string[] = []) {
  const summarize = (vs: { id: string; nodes: { target: unknown[] }[] }[]) =>
    vs.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);

  const page_ = await new AxeBuilder({ page }).withTags(TAGS).disableRules(extraDisabled).exclude(SHARE_CARD).analyze();
  expect(summarize(page_.violations)).toEqual([]);

  if ((await page.locator(SHARE_CARD).count()) > 0) {
    const card = await new AxeBuilder({ page }).withTags(TAGS).disableRules([...SHARE_CARD_WAIVED, ...extraDisabled]).include(SHARE_CARD).analyze();
    expect(summarize(card.violations)).toEqual([]);
  }
}

let user: { email: string; password: string; id: string };

function seedEntries(names: string[]) {
  psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
  for (const [i, name] of names.entries()) {
    psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, protein_g, entry_name, created_at)
          VALUES (${user.id}, '${TODAY}', ${100 * (i + 1)}, 10, '${name}', now() - interval '${names.length - i} minutes')`);
  }
}

test.describe('Accessibility', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('a11y');
    psql(`UPDATE users SET timezone = 'UTC', onboarding_completed_at = now() WHERE id = ${user.id}`);
  });

  test.afterAll(() => {
    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
  });

  test('axe: login page has no violations', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await page.goto('/login');
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await expectNoViolations(page);
    await ctx.close();
  });

  test('axe: dashboard, add-food dialog, settings and plan have no violations', async ({ browser }) => {
    seedEntries(['Apple', 'Oatmeal']);
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await expect(page.getByRole('button', { name: 'Apple' })).toBeVisible({ timeout: 15000 });
    await expectNoViolations(page);

    await openAddFood(page);
    await expectNoViolations(page);
    await page.keyboard.press('Escape');

    for (const path of ['/settings', '/plan']) {
      await page.goto(path);
      await page.waitForLoadState('networkidle');
      await expectNoViolations(page, NO_H1_YET);
    }
    await ctx.close();
  });

  test('date pill is a named, focus-ringed button; the hidden date input is out of the tab order', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    const pill = page.getByRole('button', { name: 'Change date, currently Today' });
    await expect(pill).toBeVisible({ timeout: 15000 });

    // Tab from the top of the page until the pill or the hidden input takes
    // focus; it must be the pill.
    let reached = '';
    for (let i = 0; i < 40 && !reached; i++) {
      await page.keyboard.press('Tab');
      reached = await page.evaluate(() => {
        const el = document.activeElement as HTMLElement | null;
        if (el?.matches('input[type="date"]') && !el.closest('form')) return 'input';
        if (el?.getAttribute('aria-label')?.startsWith('Change date')) return 'pill';
        return '';
      });
    }
    expect(reached).toBe('pill');
    // Our ring (2px solid, ring colour), not the UA's `auto` outline or none.
    const outline = await pill.evaluate((el) => getComputedStyle(el).outlineStyle);
    expect(outline).toBe('solid');
    // And the next Tab must not land on the invisible date input behind it.
    await page.keyboard.press('Tab');
    expect(await page.evaluate(() => (document.activeElement as HTMLElement | null)?.matches('input[type="date"]'))).toBe(false);
    await ctx.close();
  });

  test('add-food dialog focuses the first field and returns focus to the FAB', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    const fab = page.getByRole('button', { name: 'Add food' });
    await fab.focus();
    await page.keyboard.press('Enter');
    const dialog = page.getByRole('dialog', { name: 'Add food' });
    await expect(dialog.getByRole('textbox', { name: 'Food name' })).toBeFocused();

    // Shift+Tab from the first tabbable element wraps to the last, inside.
    for (let i = 0; i < 30; i++) {
      await page.keyboard.press('Shift+Tab');
      expect(await dialog.evaluate((d) => d.contains(document.activeElement))).toBe(true);
    }

    await page.keyboard.press('Escape');
    await expect(dialog).toBeHidden();
    await expect(fab).toBeFocused();
    await ctx.close();
  });

  test('on touch the add-food dialog focuses its heading, so no keyboard pops up', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, hasTouch: true, isMobile: true, viewport: { width: 390, height: 844 } });
    const page = await ctx.newPage();
    await page.goto('/login');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL('**/dashboard', { timeout: 15000 });
    expect(await page.evaluate(() => matchMedia('(pointer: coarse)').matches)).toBe(true);

    await page.getByRole('button', { name: 'Add food' }).tap();
    const dialog = page.getByRole('dialog', { name: 'Add food' });
    await expect(dialog.getByRole('heading', { name: 'Add food' })).toBeFocused();
    expect(await page.evaluate(() => document.activeElement?.tagName)).not.toBe('INPUT');
    await ctx.close();
  });

  test('deleting an entry keeps keyboard focus in the list', async ({ browser }) => {
    seedEntries(['Apple', 'Oatmeal']);
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await expect(page.getByRole('button', { name: 'Oatmeal' })).toBeVisible({ timeout: 15000 });

    const deletes = page.getByRole('button', { name: 'Delete entry' });
    await deletes.first().focus();
    await page.keyboard.press('Enter');
    await expect(deletes).toHaveCount(1);
    await expect(deletes.first()).toBeFocused();

    // Past the double-press window, a deliberate second press goes through.
    await page.waitForTimeout(500);
    await page.keyboard.press('Enter');
    await expect(deletes).toHaveCount(0);
    await expect(page.getByRole('heading', { name: 'Entries' })).toBeFocused();
    await ctx.close();
  });

  test('a held Enter deletes only one entry', async ({ browser }) => {
    seedEntries(['Apple', 'Oatmeal', 'Pasta']);
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    const deletes = page.getByRole('button', { name: 'Delete entry' });
    await expect(deletes).toHaveCount(3, { timeout: 15000 });

    // Held: keyboard.down on a key that is already down sends repeat: true,
    // spaced like a real key repeat (well past the double-press window).
    await deletes.first().focus();
    await page.keyboard.down('Enter');
    for (let i = 0; i < 3; i++) {
      await page.waitForTimeout(500);
      await page.keyboard.down('Enter');
    }
    await page.keyboard.up('Enter');
    await expect(deletes).toHaveCount(2);
    await page.waitForTimeout(500);
    await expect(deletes).toHaveCount(2);
    await expect(deletes.first()).toBeFocused();

    // The double-press window (a second keyboard delete within 400ms) is
    // covered by EntryList.focus.test.tsx with a controlled clock: here the
    // gap would depend on how fast the delete request returns.
    await ctx.close();
  });

  test('an inline edit confirms the save without a toast', async ({ browser }) => {
    seedEntries(['Apple']);
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.getByRole('button', { name: /^Calories.*kcal$/ }).first().click({ timeout: 15000 });
    const input = page.getByRole('textbox', { name: 'Calories for Apple' });
    await input.fill('321');
    await input.press('Enter');

    await expect(page.getByTestId('entry-saved')).toBeVisible();
    await expect(page.locator('[aria-live="polite"]').filter({ hasText: 'Calories for Apple saved' })).toHaveCount(1);
    await expect(page.getByRole('button', { name: /^Calories.*kcal$/ }).first()).toBeFocused();
    await ctx.close();
  });
});
