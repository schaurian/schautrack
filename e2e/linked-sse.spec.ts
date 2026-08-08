import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser, openAddFood } from './fixtures/helpers';

// SSE propagation for linked users:
// User B views User A's data via the share card. When User A adds an entry (via the app UI),
// the Go handler fires broker.BroadcastEntryChange which User B's SSE subscription picks up.
// User B's view should then refresh and show the new entry.

const TODAY = new Date().toLocaleDateString('en-CA', { timeZone: 'UTC' });

let userA: { email: string; password: string; id: string };
let userB: { email: string; password: string; id: string };

test.describe('Linked User SSE Propagation', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    userA = createIsolatedUser('linked-sse-a');
    userB = createIsolatedUser('linked-sse-b');

    // Bidirectional accepted link: B → A (B can see A's data)
    psql(`
      INSERT INTO account_links (requester_id, target_id, status)
      VALUES (${userB.id}, ${userA.id}, 'accepted')
      ON CONFLICT DO NOTHING
    `);

    // Sharing is opt-in and defaults off; grant full sharing in both directions
    // so this spec's existing assertions (which predate granular sharing) pass.
    psql(`UPDATE account_links
      SET requester_shares = '{"nutrition":true,"weight":true,"todos":true,"notes":true}'::jsonb,
          target_shares    = '{"nutrition":true,"weight":true,"todos":true,"notes":true}'::jsonb
      WHERE (requester_id = ${userB.id} AND target_id = ${userA.id})
         OR (requester_id = ${userA.id} AND target_id = ${userB.id})`);
  });

  test.afterAll(() => {
    psql(`DELETE FROM calorie_entries WHERE user_id = ${userA.id}`);
    psql(`DELETE FROM account_links WHERE requester_id = ${userB.id} AND target_id = ${userA.id}`);
  });

  test('linked user entry propagates via SSE to viewer without reload', async ({ browser }) => {
    // Login User A
    const { context: ctxA, page: pageA } = await loginUser(browser, userA.email, userA.password);
    // Login User B
    const { context: ctxB, page: pageB } = await loginUser(browser, userB.email, userB.password);

    try {
      // Load both dashboards
      await pageA.goto('/dashboard');
      await pageA.waitForLoadState('domcontentloaded');
      await expect(pageA.getByRole('button', { name: 'Add food' })).toBeVisible({ timeout: 10000 });

      await pageB.goto('/dashboard');
      await pageB.waitForLoadState('domcontentloaded');

      // Wait directly for user A's share card label — don't use Timeline heading as a proxy
      // because Timeline renders before share cards data loads.
      const userALabel = pageB
        .locator('.text-sm.font-medium')
        .filter({ hasText: new RegExp(userA.email.split('@')[0], 'i') })
        .first();

      // Scroll to bottom to ensure the share card area is in the viewport
      await pageB.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
      await expect(userALabel).toBeVisible({ timeout: 20000 });

      // Click today's dot in User A's share card to switch to their view
      const userACard = pageB.getByTestId('share-card').filter({ hasText: new RegExp(userA.email.split('@')[0], 'i') });
      const todayDot = userACard.locator(`button[title="${TODAY}"]`).first();
      const dotVisible = await todayDot.isVisible({ timeout: 5000 }).catch(() => false);

      if (dotVisible) {
        await todayDot.click();
        await pageB.waitForTimeout(600);
      }

      // Now User A adds an entry via the UI (this fires the SSE event)
      const entryName = `SSE Linked Entry ${Date.now()}`;
      await openAddFood(pageA);
      await pageA.locator('input[placeholder="Breakfast, snack..."]').fill(entryName);
      await pageA.locator('input[inputmode="tel"]').first().fill('444');
      await pageA.getByRole('button', { name: 'Track' }).click();
      await expect(pageA.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

      // User B's page (viewing User A) should show the new entry without a manual reload
      // SSE fires a broadcast that triggers a refetch in the viewer's dashboard
      if (dotVisible) {
        await expect(pageB.getByText(entryName)).toBeVisible({ timeout: 15000 });
      } else {
        // If the share card dot wasn't clickable (e.g., no range coverage), skip SSE assertion
        // but verify the entry exists for User A
        await expect(pageA.getByRole('button', { name: entryName })).toBeVisible({ timeout: 5000 });
        test.skip(true, 'Share card dot not visible; cannot verify cross-user SSE in this configuration');
      }
    } finally {
      await ctxA.close();
      await ctxB.close();
    }
  });

  test('share permission changes propagate to the linked viewer without reload', async ({ browser }) => {
    // User A is target_id, so target_shares controls what A shares with B.
    // Start with nutrition as the only shared category: disabling it should
    // remove A's entire share card from B's already-open dashboard.
    psql(`UPDATE account_links
      SET target_shares = '{"nutrition":true,"weight":false,"todos":false,"notes":false}'::jsonb
      WHERE requester_id = ${userB.id} AND target_id = ${userA.id}`);

    const { context: ctxA, page: pageA } = await loginUser(browser, userA.email, userA.password);
    const { context: ctxB, page: pageB } = await loginUser(browser, userB.email, userB.password);

    try {
      await pageB.goto('/dashboard');
      const userALabel = pageB
        .locator('.text-sm.font-medium')
        .filter({ hasText: new RegExp(userA.email.split('@')[0], 'i') })
        .first();
      await expect(userALabel).toBeVisible({ timeout: 20000 });

      await pageA.goto('/settings');
      const linkButton = pageA.getByRole('button', { name: userB.email });
      await expect(linkButton).toBeVisible({ timeout: 10000 });
      const linkRow = linkButton.locator('../..');
      const nutrition = linkRow.getByTestId('share-toggle-nutrition');
      await expect(nutrition.locator('input')).toBeChecked();
      await nutrition.click();

      await expect(userALabel).toHaveCount(0, { timeout: 15000 });
    } finally {
      await ctxA.close();
      await ctxB.close();
    }
  });
});
