import { test, expect, type Locator, type Page } from '@playwright/test';
import { createIsolatedUser, openAddFood, psql } from './fixtures/helpers';

/**
 * Tapping a piece of text to edit it in place swaps it for an <input>. That swap
 * must be invisible apart from the edit ring: same font size, weight,
 * line-height and family, same box height, and the text must not move.
 *
 * Regression: every inline editor hard-coded its own `text-sm` input while the
 * text it replaced was styled differently (entry name 15px/600 -> 14px/400,
 * share-card label 500 -> 400, ...), and the editing macro pill was a larger
 * rounded-full pill (row +4px, neighbours pushed ~12px right). The shared
 * InlineEditInput now inherits its font from a wrapper common to both modes.
 * jsdom computes no Tailwind styles, so this has to be a browser test.
 */

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
const ENTRY = 'Typography Apple';
const SAVED_FOOD = 'Typography Oats';
const LINK_LABEL = 'Typography Partner';
const PASSKEY = 'Typography Key';

type Metrics = {
  fontSize: string;
  fontWeight: string;
  lineHeight: string;
  fontFamily: string;
  letterSpacing: string;
  height: number;
  /**
   * Where the glyphs start (border-box + border + padding), relative to the
   * parent element. Display and input share the same parent at every call site,
   * and measuring relative to it keeps unrelated page shifts (a toast, a
   * refetch) out of the comparison.
   */
  textX: number;
  textY: number;
};

const round = (n: number) => Math.round(n * 4) / 4;

function metrics(loc: Locator): Promise<Metrics> {
  return loc.evaluate((el) => {
    const s = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    const p = (el.parentElement ?? el).getBoundingClientRect();
    const q = (n: number) => Math.round(n * 4) / 4;
    return {
      fontSize: s.fontSize,
      fontWeight: s.fontWeight,
      lineHeight: s.lineHeight,
      fontFamily: s.fontFamily,
      letterSpacing: s.letterSpacing,
      height: q(r.height),
      textX: q(r.x - p.x + parseFloat(s.borderLeftWidth) + parseFloat(s.paddingLeft)),
      textY: q(r.y - p.y + parseFloat(s.borderTopWidth) + parseFloat(s.paddingTop)),
    };
  });
}

/** Content-box left edge of an element's parent, relative to that parent: where un-padded text starts. */
function parentContentLeft(loc: Locator): Promise<number> {
  return loc.evaluate((el) => {
    const s = getComputedStyle(el.parentElement ?? el);
    return Math.round((parseFloat(s.borderLeftWidth) + parseFloat(s.paddingLeft)) * 4) / 4;
  });
}

/** Click `display`, measure the focused input, and assert nothing but the ring changed. */
async function expectSeamlessEdit(page: Page, display: Locator, expectedValue: string) {
  await expect(display).toBeVisible();
  await display.scrollIntoViewIfNeeded();
  const before = await metrics(display);
  await display.click();
  const input = page.locator('input:focus');
  await expect(input).toHaveValue(expectedValue);
  const during = await metrics(input);
  expect(during).toEqual(before);
  return { before, input };
}

for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
  test.describe(`inline edit keeps its typography @${viewport.width}px`, () => {
    let user: { email: string; password: string; id: string };

    test.beforeAll(() => {
      user = createIsolatedUser(`inline-edit-typography-${viewport.width}`);
      const partner = createIsolatedUser(`inline-edit-typography-partner-${viewport.width}`);
      // createIsolatedUser does not clean links or passkeys; reset them here.
      psql(`DELETE FROM account_links WHERE requester_id IN (${user.id}, ${partner.id}) OR target_id IN (${user.id}, ${partner.id});
        DELETE FROM user_passkeys WHERE user_id = ${user.id};
        INSERT INTO account_links (requester_id, target_id, status, requester_label, requester_shares, target_shares)
          VALUES (${user.id}, ${partner.id}, 'accepted', :'label', '{"nutrition": true}', '{"nutrition": true}');
        INSERT INTO saved_foods (user_id, name, amount) VALUES (${user.id}, :'food', 120);
        INSERT INTO user_passkeys (user_id, credential_id, public_key, name)
          VALUES (${user.id}, decode(md5(random()::text), 'hex'), decode(md5(random()::text), 'hex'), :'passkey');`,
        { label: LINK_LABEL, food: SAVED_FOOD, passkey: PASSKEY });
    });

    // Fresh context: the chromium project's default storageState is the shared test user.
    test.use({ viewport, storageState: { cookies: [], origins: [] } });

    async function login(page: Page) {
      await page.goto(`${baseURL}/login`);
      await page.getByLabel('Email').fill(user.email);
      await page.getByLabel('Password').fill(user.password);
      await page.getByRole('button', { name: 'Log In' }).click();
      await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    }

    test('entry name and macro pills', async ({ page }) => {
      await login(page);
      await openAddFood(page);
      await page.locator('input[placeholder="Breakfast, snack..."]').fill(ENTRY);
      await page.locator('input[inputmode="tel"][placeholder="0"]').first().fill('250');
      await page.locator('form button[type="submit"]').click();
      await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

      // --- entry name ---
      await expectSeamlessEdit(page, page.getByRole('button', { name: ENTRY, exact: true }), ENTRY);
      await page.keyboard.press('Escape');

      // --- calories pill: same box, neighbour pill does not move ---
      // Boxes are taken relative to the pill row, so a scroll on click cancels out.
      const kcal = page.getByRole('button', { name: /^Calories\b/ }).first();
      await kcal.scrollIntoViewIfNeeded();
      // A handle, not a locator: the locator would re-resolve through the
      // Calories button, which no longer exists once it has become an input.
      const pillRow = await kcal.evaluateHandle((el) => el.parentElement as HTMLElement);
      const boxes = () => pillRow.evaluate((row) => {
        const o = row.getBoundingClientRect();
        const [kcalPill, proteinPill] = [row.children[0], row.children[1]].map((c) => c.getBoundingClientRect());
        return {
          rowHeight: o.height,
          kcal: { x: kcalPill.x - o.x, y: kcalPill.y - o.y, w: kcalPill.width, h: kcalPill.height },
          protein: { x: proteinPill.x - o.x, y: proteinPill.y - o.y },
        };
      });
      const before = await boxes();
      const valueBefore = await metrics(kcal.locator('span.font-bold'));

      await kcal.click();
      const kcalInput = page.locator('input:focus');
      await expect(kcalInput).toHaveValue('250');
      const during = await boxes();
      expect(round(during.rowHeight)).toBe(round(before.rowHeight));
      expect(round(during.kcal.h)).toBe(round(before.kcal.h));
      expect(round(during.kcal.y)).toBe(round(before.kcal.y));
      expect(round(during.protein.y)).toBe(round(before.protein.y));
      // The pill may widen by the caret slack of the `ch`-sized input, but not
      // by a whole extra padding/radius change as before (~12px).
      expect(Math.abs(during.kcal.w - before.kcal.w)).toBeLessThanOrEqual(4);
      expect(Math.abs(during.protein.x - before.protein.x)).toBeLessThanOrEqual(4);

      const valueDuring = await metrics(kcalInput);
      expect({ ...valueDuring, height: 0, textX: 0, textY: 0 }).toEqual({ ...valueBefore, height: 0, textX: 0, textY: 0 });
      await page.keyboard.press('Escape');
    });

    test('share-card label', async ({ page }) => {
      await login(page);
      const card = page.getByTestId('share-card').filter({ hasText: LINK_LABEL });
      const labelButton = card.getByRole('button', { name: `Edit label for ${LINK_LABEL}` });
      await expectSeamlessEdit(page, labelButton, LINK_LABEL);
      await page.keyboard.press('Escape');
    });

    test('saved-food name in the manage dialog', async ({ page }) => {
      await login(page);
      // The saved-foods row lives in the add-food sheet; Manage opens a second dialog.
      const sheet = await openAddFood(page);
      await sheet.getByTestId('saved-foods-row').getByRole('button', { name: 'Manage', exact: true }).click();
      const dialog = page.getByRole('dialog').filter({ has: page.getByRole('button', { name: SAVED_FOOD, exact: true }) }).last();
      await expect(dialog).toBeVisible();
      await expectSeamlessEdit(page, dialog.getByRole('button', { name: SAVED_FOOD, exact: true }), SAVED_FOOD);
      await page.keyboard.press('Escape');
    });

    test('link label in settings', async ({ page }) => {
      await login(page);
      await page.goto(`${baseURL}/settings`);
      const display = page.getByTestId('link-row').getByRole('button', { name: LINK_LABEL, exact: true });
      await expect(display).toBeVisible({ timeout: 10000 });
      // The display text must stay flush with the row, as it was before it got padding.
      expect((await metrics(display)).textX).toBe(await parentContentLeft(display));
      await expectSeamlessEdit(page, display, LINK_LABEL);
    });

    test('passkey name in account', async ({ page }) => {
      await login(page);
      await page.goto(`${baseURL}/account`);
      const display = page.getByRole('button', { name: PASSKEY, exact: true });
      await expect(display).toBeVisible({ timeout: 10000 });
      expect((await metrics(display)).textX).toBe(await parentContentLeft(display));
      await expectSeamlessEdit(page, display, PASSKEY);
    });
  });
}
