import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser } from './fixtures/helpers';

/**
 * Quick-add sharing, end to end across two real accounts (#537).
 *
 * The unit tests cover the predicate and the chip row separately; what only an
 * e2e run can show is the whole loop working against one another: the owner
 * ticks a category, the friend's dashboard grows a chip, tapping it writes an
 * entry to the FRIEND'S account and not the owner's, and unticking it takes
 * the chip away again.
 *
 * Revocation is asserted because the design leans on it: nothing is copied, so
 * "untick and it is gone" is the entire cleanup story. A test that only proved
 * sharing works would leave that claim unchecked.
 */

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';

let owner: { email: string; password: string; id: string };
let friend: { email: string; password: string; id: string };

function clearLinks() {
  if (!owner?.id || !friend?.id) return;
  psql(
    `DELETE FROM account_links WHERE (requester_id = ${owner.id} AND target_id = ${friend.id}) OR (requester_id = ${friend.id} AND target_id = ${owner.id})`,
  );
}

/** Links the two accounts directly, with the owner sharing `shares`. */
function linkWithShares(shares: string) {
  clearLinks();
  psql(
    `INSERT INTO account_links (requester_id, target_id, status, requester_shares, target_shares)
     VALUES (${owner.id}, ${friend.id}, 'accepted', '${shares}'::jsonb, '{}'::jsonb)`,
  );
}

test.describe('Shared quick-adds', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    owner = createIsolatedUser('sqa-owner');
    friend = createIsolatedUser('sqa-friend');
    clearLinks();
    psql(`DELETE FROM saved_foods WHERE user_id = ${owner.id} OR user_id = ${friend.id}`);
    psql(
      `INSERT INTO saved_foods (user_id, name, amount, protein_g) VALUES (${owner.id}, 'Owner Oats', 321, 12)`,
    );
  });

  test.afterAll(() => {
    clearLinks();
    psql(`DELETE FROM saved_foods WHERE user_id = ${owner.id} OR user_id = ${friend.id}`);
  });

  /**
   * Logs in and opens the add-food sheet, because that is the only place the
   * quick-add row is mounted — `Sheet` unmounts its subtree when closed, so a
   * dashboard-level assertion would find nothing whether or not sharing works.
   * The negative tests below depend on this too: a `toHaveCount(0)` taken
   * against a closed sheet passes for the wrong reason.
   */
  async function loginAsFriend(browser: import('@playwright/test').Browser) {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(friend.email);
    await page.getByLabel('Password').fill(friend.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    // Wait for the list call the row fires on mount, not just for the sheet to
    // appear. The two "nothing is shared" tests assert an absence, and an
    // absence is true before the response lands as well as after — without this
    // they would pass on an unanswered query.
    const listed = page.waitForResponse(
      (r) => r.url().includes('/api/saved-foods') && r.url().includes('scope=all'),
      { timeout: 15000 },
    );
    await page.getByRole('button', { name: 'Add food' }).click();
    await expect(page.getByRole('dialog', { name: 'Add food' })).toBeVisible({ timeout: 15000 });
    await listed;
    // Scope every chip assertion to the quick-add row. Unscoped, /Owner Oats/
    // also matches the timeline entry the first test logs, which sits behind
    // the sheet — the two "shares nothing" tests then fail on a button that has
    // nothing to do with sharing.
    return { ctx, page, chip: page.getByTestId('saved-foods-row').getByRole('button', { name: /Owner Oats/ }) };
  }

  test('a linked friend sees and can log a shared quick-add', async ({ browser }) => {
    linkWithShares('{"savedfoods": true}');

    const { ctx, page, chip } = await loginAsFriend(browser);
    try {
      // The friend has no quick-adds of their own, so the row exists purely
      // because of the share — and the chip must be reachable straight away,
      // without unfolding the "+ more" overflow.
      await expect(chip).toBeVisible({ timeout: 15000 });
      await expect(page.getByTestId('saved-foods-shared')).toBeVisible();

      await chip.click();

      // The entry lands on the FRIEND. That is the whole point: a borrowed
      // food is logged to whoever tapped it.
      await expect
        .poll(
          () =>
            psql(
              `SELECT count(*) FROM calorie_entries WHERE user_id = ${friend.id} AND amount = 321`,
            ).trim(),
          { timeout: 15000 },
        )
        .toBe('1');

      // ...and not on the owner.
      expect(
        psql(`SELECT count(*) FROM calorie_entries WHERE user_id = ${owner.id}`).trim(),
      ).toBe('0');

      // The owner's ranking counters are untouched: use_count drives chip
      // order, so a friend's usage must not reorder the owner's own row.
      expect(
        psql(`SELECT use_count FROM saved_foods WHERE user_id = ${owner.id}`).trim(),
      ).toBe('0');
    } finally {
      await ctx.close();
    }
  });

  test('unticking the category takes the chip away', async ({ browser }) => {
    linkWithShares('{"savedfoods": false}');

    const { ctx, page, chip } = await loginAsFriend(browser);
    try {
      // The friend still has no foods of their own, so with the share off the
      // row renders nothing at all.
      await expect(chip).toHaveCount(0, { timeout: 15000 });
      await expect(page.getByTestId('saved-foods-shared')).toHaveCount(0);
    } finally {
      await ctx.close();
    }
  });

  test('an accepted link without the category shares nothing', async ({ browser }) => {
    // Every other category on, savedfoods off: being linked is not enough.
    linkWithShares('{"nutrition": true, "weight": true, "todos": true, "notes": true}');

    const { ctx, chip } = await loginAsFriend(browser);
    try {
      await expect(chip).toHaveCount(0, { timeout: 15000 });
    } finally {
      await ctx.close();
    }
  });
});
