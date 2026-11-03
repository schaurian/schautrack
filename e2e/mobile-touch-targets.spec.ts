import { test, expect, type Locator, type Page } from '@playwright/test';
import { createIsolatedUser, loginUser, psql } from './fixtures/helpers';

// Mobile layout guarantees for the dashboard (the Android app is a WebView of
// this client, so this is the app's layout):
//  - every frequently tapped control has a hit area of at least 44x44 CSS px;
//  - the destructive entry action is not flush against save-as-quick-add;
//  - at the end of the page nothing interactive, and not the last card, sits
//    under the floating add-food button.
// Bounding boxes are what is asserted: a class name says nothing about layout.

const MIN_TARGET = 44;
let user: { email: string; password: string; id: string };

type Box = { x: number; y: number; width: number; height: number };

async function box(locator: Locator): Promise<Box> {
  const b = await locator.boundingBox();
  if (!b) throw new Error('element has no bounding box');
  return b;
}

const intersects = (a: Box, b: Box) =>
  a.x < b.x + b.width && b.x < a.x + a.width && a.y < b.y + b.height && b.y < a.y + a.height;

async function openDashboard(browser: import('@playwright/test').Browser, width: number): Promise<{ page: Page; close: () => Promise<void> }> {
  const { context, page } = await loginUser(browser, user.email, user.password);
  await page.setViewportSize({ width, height: 844 });
  await page.goto('/dashboard');
  await expect(page.getByRole('button', { name: 'Delete entry' }).first()).toBeVisible({ timeout: 15000 });
  await expect(page.getByRole('button', { name: /^Check / }).first()).toBeVisible({ timeout: 15000 });
  return { page, close: () => context.close() };
}

test.describe('Mobile touch targets and FAB clearance', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('touch-targets');
    psql(`UPDATE users SET onboarding_completed_at = NOW() WHERE id = ${user.id}`);
    psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name)
          SELECT ${user.id}, CURRENT_DATE, 100 + g, 'Touch entry ' || g FROM generate_series(1, 4) g`);
    psql(`INSERT INTO todos (user_id, name, sort_order)
          VALUES (${user.id}, 'Touch todo one', 1), (${user.id}, 'Touch todo two', 2)`);
  });

  for (const width of [360, 390]) {
    test(`dashboard targets are at least 44x44 at ${width}px`, async ({ browser }) => {
      const { page, close } = await openDashboard(browser, width);

      const targets: [string, Locator][] = [
        ['todo checkbox', page.getByRole('button', { name: /^Check / }).first()],
        ['timeline day dot', page.getByTestId('share-card').first().locator('button[title]').first()],
        ['save as quick-add', page.getByRole('button', { name: 'Save as quick-add' }).first()],
        ['delete entry', page.getByRole('button', { name: 'Delete entry' }).first()],
      ];
      for (const [name, locator] of targets) {
        const b = await box(locator);
        expect(b.width, `${name} width`).toBeGreaterThanOrEqual(MIN_TARGET);
        expect(b.height, `${name} height`).toBeGreaterThanOrEqual(MIN_TARGET);
      }

      // Neighbouring todo checkboxes and day dots must not share hit area.
      const checks = page.getByRole('button', { name: /^Check / });
      expect(intersects(await box(checks.nth(0)), await box(checks.nth(1))), 'todo hit areas overlap').toBe(false);
      const dots = page.getByTestId('share-card').first().locator('button[title]');
      expect(intersects(await box(dots.nth(0)), await box(dots.nth(1))), 'day-dot hit areas overlap').toBe(false);

      // No day-of-month number: each dot button holds only its 22px square
      // and carries no text (the date is in its title and label).
      const contents = await dots.evaluateAll((els) => els.map((el) => ({ children: el.children.length, text: el.textContent ?? '' })));
      expect(contents.length, 'day dots rendered').toBeGreaterThan(0);
      for (const c of contents) {
        expect(c.children, 'day dot children (square only, no day number)').toBe(1);
        expect(c.text, 'day dot text (no day number)').toBe('');
      }
      // Compact as before the 44px hit areas: 8px under the last row of
      // squares plus the card's 6px padding (it was 21px with the grid's own
      // padding on top of the hit-area margin).
      const tail = await page.getByTestId('share-card').first().evaluate((card) => {
        const squares = [...card.querySelectorAll('button[title] > span')].map((s) => s.getBoundingClientRect().bottom);
        return card.getBoundingClientRect().bottom - Math.max(...squares);
      });
      expect(tail, 'space under the last row of day squares').toBeLessThanOrEqual(15);

      // Delete is separated from save-as-quick-add by a dead zone, not flush.
      const save = await box(page.getByRole('button', { name: 'Save as quick-add' }).first());
      const del = await box(page.getByRole('button', { name: 'Delete entry' }).first());
      expect(del.x - (save.x + save.width), 'gap between save-as-quick-add and delete').toBeGreaterThanOrEqual(8);

      await close();
    });

    test(`FAB covers nothing at the end of the page at ${width}px`, async ({ browser }) => {
      const { page, close } = await openDashboard(browser, width);
      await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
      // Let the scroll settle before measuring.
      await page.waitForFunction(() => Math.ceil(window.scrollY + window.innerHeight) >= document.documentElement.scrollHeight - 1);

      const fab = await box(page.getByRole('button', { name: 'Add food' }));
      const covered = await page.evaluate((f) => {
        const hit = (r: DOMRect) => r.width > 0 && r.left < f.x + f.width && f.x < r.right && r.top < f.y + f.height && f.y < r.bottom;
        const out: string[] = [];
        for (const el of document.querySelectorAll('main a[href], main button, main input, main textarea, main [role=button], footer a[href]')) {
          if (el.hasAttribute('data-fab')) continue;
          if (hit(el.getBoundingClientRect())) out.push(el.getAttribute('aria-label') || el.getAttribute('href') || el.textContent?.trim() || el.tagName);
        }
        const cards = document.querySelectorAll('main section');
        const last = cards[cards.length - 1];
        if (last && hit(last.getBoundingClientRect())) out.push('last card');
        return out;
      }, fab);
      expect(covered, 'elements under the FAB at the end of the page').toEqual([]);

      // Not just "no overlap": the footer and the last card end clear above the
      // FAB's top edge, so the guarantee holds at every width, not only where
      // a footer link happens to sit under the FAB.
      const footer = await box(page.locator('footer'));
      expect(footer.y + footer.height, 'footer bottom vs FAB top').toBeLessThanOrEqual(fab.y - 8);
      const lastCard = await box(page.locator('main section').last());
      expect(lastCard.y + lastCard.height, 'last card bottom vs FAB top').toBeLessThanOrEqual(fab.y - 16);

      await close();
    });
  }

  for (const width of [768, 1280]) {
    test(`timeline dots spread across the full card width at ${width}px`, async ({ browser }) => {
      const { page, close } = await openDashboard(browser, width);
      const card = page.getByTestId('share-card').first();
      const cardBox = await box(card);
      const rights = await card.locator('button[title]').evaluateAll((els) => els.map((el) => el.getBoundingClientRect().right));
      const lastRight = Math.max(...rights);
      // The rightmost hit area reaches the card's right edge; with empty grid
      // tracks kept (auto-fill) it stopped hundreds of px short on wide screens.
      expect(cardBox.x + cardBox.width - lastRight, 'gap right of the last day dot').toBeLessThanOrEqual(12);
      await close();
    });
  }

  test('desktop keeps no tab-bar clearance under the footer at 1280px', async ({ browser }) => {
    const { page, close } = await openDashboard(browser, 1280);
    const pb = await page.locator('footer').evaluate((el) => getComputedStyle(el.parentElement as HTMLElement).paddingBottom);
    expect(pb).toBe('0px');
    await close();
  });
});
