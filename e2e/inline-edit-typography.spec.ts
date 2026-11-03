import { test, expect, type Locator, type Page } from '@playwright/test';
import { createIsolatedUser, openAddFood } from './fixtures/helpers';

/**
 * Tapping an entry's name or a macro pill swaps the text for an <input>. That
 * swap must be invisible apart from the edit ring: same font size, weight,
 * line-height and family, and the same box, so nothing jumps.
 *
 * Regression: the name input hard-coded `text-sm` (14px/400) while the name
 * showed at 15px/600, so the text shrank and lost its weight on tap; and the
 * editing pill was a larger rounded-full pill (row +4px, neighbours pushed
 * ~12px right). jsdom computes no Tailwind styles, so this has to be a browser
 * test.
 */

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
const ENTRY = 'Typography Apple';

type Metrics = { fontSize: string; fontWeight: string; lineHeight: string; fontFamily: string; height: number };

function metrics(loc: Locator): Promise<Metrics> {
  return loc.evaluate((el) => {
    const s = getComputedStyle(el);
    return {
      fontSize: s.fontSize,
      fontWeight: s.fontWeight,
      lineHeight: s.lineHeight,
      fontFamily: s.fontFamily,
      height: Math.round(el.getBoundingClientRect().height * 10) / 10,
    };
  });
}

async function boxOf(loc: Locator) {
  const b = await loc.boundingBox();
  if (!b) throw new Error('element has no box');
  return b;
}

for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
  test.describe(`inline edit keeps its typography @${viewport.width}px`, () => {
    let user: { email: string; password: string; id: string };

    test.beforeAll(() => {
      user = createIsolatedUser(`inline-edit-typography-${viewport.width}`);
    });

    // Fresh context: the chromium project's default storageState is the shared test user.
    test.use({ viewport, storageState: { cookies: [], origins: [] } });

    async function setup(page: Page) {
      await page.goto(`${baseURL}/login`);
      await page.getByLabel('Email').fill(user.email);
      await page.getByLabel('Password').fill(user.password);
      await page.getByRole('button', { name: 'Log In' }).click();
      await page.waitForURL(/\/dashboard/, { timeout: 15000 });
      await openAddFood(page);
      await page.locator('input[placeholder="Breakfast, snack..."]').fill(ENTRY);
      await page.locator('input[inputmode="tel"][placeholder="0"]').first().fill('250');
      await page.locator('form button[type="submit"]').click();
      await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });
    }

    test('entry name and macro pills do not change size when edited', async ({ page }) => {
      await setup(page);

      // --- entry name ---
      const name = page.getByRole('button', { name: ENTRY, exact: true });
      await expect(name).toBeVisible();
      const before = await metrics(name);
      await name.click();
      const input = page.locator('input:focus');
      await expect(input).toHaveValue(ENTRY);
      const during = await metrics(input);
      expect(during).toEqual(before);
      await page.keyboard.press('Escape');

      // --- calories pill: same box, neighbour pill does not move ---
      const kcal = page.getByRole('button', { name: /^Calories\b/ }).first();
      const protein = page.getByRole('button', { name: /^Protein\b/ }).first();
      await expect(kcal).toBeVisible();
      const kcalBox = await boxOf(kcal);
      const proteinBefore = await boxOf(protein);
      const valueBefore = await metrics(kcal.locator('span.font-bold'));

      await kcal.click();
      const kcalInput = page.locator('input:focus');
      await expect(kcalInput).toHaveValue('250');
      const pillBox = await boxOf(kcalInput.locator('xpath=..'));
      expect(pillBox.height).toBeCloseTo(kcalBox.height, 0);
      expect(pillBox.y).toBeCloseTo(kcalBox.y, 0);
      // The pill may widen by the caret slack of the `ch`-sized input, but not
      // by a whole extra padding/radius change as before (~12px).
      expect(Math.abs(pillBox.width - kcalBox.width)).toBeLessThanOrEqual(4);
      const proteinDuring = await boxOf(protein);
      expect(proteinDuring.y).toBeCloseTo(proteinBefore.y, 0);
      expect(Math.abs(proteinDuring.x - proteinBefore.x)).toBeLessThanOrEqual(4);

      const valueDuring = await metrics(kcalInput);
      expect({ ...valueDuring, height: 0 }).toEqual({ ...valueBefore, height: 0 });
      await page.keyboard.press('Escape');
    });
  });
}
