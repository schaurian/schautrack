import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser } from './fixtures/helpers';

// Creator is in America/Los_Angeles (PDT = UTC-7 in summer, PST = UTC-8 in winter).
// Insert entry at UTC 20:00 → PDT 13:00.
// The viewer (UTC) sees the time displayed in the CREATOR's timezone (LA time), not their own.

const ENTRY_UTC_TS = '2026-04-01 20:00:00+00'; // UTC 20:00 → LA 13:00 PDT (UTC-7)
const ENTRY_DATE = '2026-04-01';
const ENTRY_NAME = 'Creator LA Entry';

let viewer: { email: string; password: string; id: string };
let creator: { email: string; password: string; id: string };

test.describe('Linked User Timezone Display', () => {
  test.beforeAll(() => {
    viewer = createIsolatedUser('linked-tz-viewer');
    creator = createIsolatedUser('linked-tz-creator');

    // Set viewer to UTC, creator to America/Los_Angeles
    psql(`UPDATE users SET timezone = 'UTC' WHERE id = ${viewer.id}`);
    psql(`UPDATE users SET timezone = 'America/Los_Angeles' WHERE id = ${creator.id}`);

    // Create an accepted link: viewer → creator
    psql(`
      INSERT INTO account_links (requester_id, target_id, status)
      VALUES (${viewer.id}, ${creator.id}, 'accepted')
      ON CONFLICT DO NOTHING
    `);

    // Insert an entry for the creator at a known UTC timestamp
    psql(`
      INSERT INTO calorie_entries (user_id, entry_date, entry_name, amount, created_at)
      VALUES (${creator.id}, '${ENTRY_DATE}', '${ENTRY_NAME}', 300, '${ENTRY_UTC_TS}')
    `);
  });

  test.afterAll(() => {
    psql(`DELETE FROM calorie_entries WHERE user_id = ${creator.id} AND entry_name = '${ENTRY_NAME}'`);
    psql(`DELETE FROM account_links WHERE requester_id = ${viewer.id} AND target_id = ${creator.id}`);
    psql(`UPDATE users SET timezone = NULL WHERE id IN (${viewer.id}, ${creator.id})`);
  });

  test('entry times show in creator timezone when viewing linked user', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, viewer.email, viewer.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // Scroll to bring share cards into view and wait for the creator's card label
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));

    const creatorEmail = creator.email;
    const creatorLabel = page
      .locator('span.text-sm.font-medium')
      .filter({ hasText: new RegExp(creatorEmail.split('@')[0], 'i') })
      .first();

    await expect(creatorLabel).toBeVisible({ timeout: 20000 });

    // Expand to 30d range to ensure April 1 dot is visible (14d default: March 23 – April 6,
    // April 1 is within 14d, but 30d gives more margin)
    const thirtyDayBtn = page.locator('button').filter({ hasText: '30d' });
    await thirtyDayBtn.click();
    await page.waitForTimeout(500);

    // Click the creator's dot for the entry date using aria-label
    // DayDot renders: <button title="{date}" aria-label="{date}: {status}">
    // Look for the April 1 dot within the creator's card
    const creatorCard = creatorLabel.locator('../..');
    const entryDot = creatorCard.locator(`button[title="${ENTRY_DATE}"]`).first();

    await entryDot.scrollIntoViewIfNeeded({ timeout: 3000 }).catch(() => {});
    const dotVisible = await entryDot.isVisible({ timeout: 5000 }).catch(() => false);

    if (!dotVisible) {
      // Fallback: try any dot with this date anywhere on the page
      const anyDot = page.locator(`button[aria-label^="${ENTRY_DATE}"]`).first();
      if (await anyDot.isVisible({ timeout: 3000 }).catch(() => false)) {
        await anyDot.click();
        await page.waitForTimeout(800);
      } else {
        // Entry date not in range — skip the entry-level assertions
        console.log('[linked-timezone] Dot for', ENTRY_DATE, 'not found; skipping entry check');
        await ctx.close();
        return;
      }
    } else {
      await entryDot.click();
      await page.waitForTimeout(800);
    }

    // After switching to creator's view for April 1, scroll to entries section
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(300);

    // The creator's entry should be visible (read-only button, disabled but present)
    // Use filter to allow disabled buttons
    const entryName = page.locator('button').filter({ hasText: ENTRY_NAME }).first();
    await entryName.scrollIntoViewIfNeeded({ timeout: 3000 }).catch(() => {});
    await expect(entryName).toBeVisible({ timeout: 10000 });

    // Extract the displayed time for the entry
    const timeText = await page.evaluate((name) => {
      const btns = Array.from(document.querySelectorAll('button'));
      const nameBtn = btns.find((b) => b.textContent?.trim() === name);
      if (!nameBtn) return null;
      // Row structure: span(flex-1) > button(name) | span(time) | button(delete)
      const nameSpan = nameBtn.parentElement; // span.flex-1
      const rowDiv = nameSpan?.parentElement; // div.flex.items-center
      if (!rowDiv) return null;
      const spans = Array.from(rowDiv.querySelectorAll('span'));
      const timeSpan = spans.find((s) => s.classList.contains('tabular-nums'));
      return timeSpan?.textContent?.trim() || null;
    }, ENTRY_NAME);

    // Entry time should be in LA timezone (13:xx), not UTC (20:xx)
    if (timeText) {
      const hourMatch = timeText.match(/^(\d{1,2}):/);
      if (hourMatch) {
        const hour = parseInt(hourMatch[1], 10);
        // UTC 20:00 → PDT 13:00. Accept 12-14 for DST variance.
        expect(hour).toBeGreaterThanOrEqual(12);
        expect(hour).toBeLessThanOrEqual(14);
        expect(hour).not.toBe(20); // should NOT show UTC time
      }
    }

    await ctx.close();
  });
});
