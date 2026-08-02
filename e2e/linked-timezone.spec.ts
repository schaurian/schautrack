import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser } from './fixtures/helpers';

// Creator is in America/Los_Angeles (PDT = UTC-7 in summer, PST = UTC-8 in winter).
// Insert entry at UTC 20:00 → PDT 13:00.
// The viewer (UTC) sees the time displayed in the CREATOR's timezone (LA time), not their own.

// Pick a recent date so the entry's dot is always inside the timeline range.
// A hardcoded date silently aged out of range and made this spec a no-op.
const recent = new Date();
recent.setUTCDate(recent.getUTCDate() - 5);
const ENTRY_DATE = recent.toISOString().slice(0, 10);
const ENTRY_UTC_TS = `${ENTRY_DATE} 20:00:00+00`; // UTC 20:00 → LA 13:00 PDT (UTC-7)
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

    // Sharing is opt-in and defaults off; grant full sharing in both directions
    // so this spec's existing assertions (which predate granular sharing) pass.
    psql(`UPDATE account_links
      SET requester_shares = '{"nutrition":true,"weight":true,"todos":true,"notes":true}'::jsonb,
          target_shares    = '{"nutrition":true,"weight":true,"todos":true,"notes":true}'::jsonb
      WHERE (requester_id = ${viewer.id} AND target_id = ${creator.id})
         OR (requester_id = ${creator.id} AND target_id = ${viewer.id})`);

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
      .locator('.text-sm.font-medium')
      .filter({ hasText: new RegExp(creatorEmail.split('@')[0], 'i') })
      .first();

    await expect(creatorLabel).toBeVisible({ timeout: 20000 });

    // Range presets sit behind the "Nd ▾" toggle in the Timeline header.
    await page.getByRole('button', { name: /^\d+d/, expanded: false }).first().click();
    await page.getByRole('button', { name: '30d', exact: true }).click();
    await page.waitForTimeout(500);

    // Click the creator's dot for the entry date. DayDot renders
    // <button title="{date}" aria-label="{date}: {status}">.
    const creatorCard = page.getByTestId('share-card').filter({ hasText: new RegExp(creatorEmail.split('@')[0], 'i') });
    const entryDot = creatorCard.locator(`button[title="${ENTRY_DATE}"]`).first();
    await entryDot.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(entryDot).toBeVisible({ timeout: 5000 });
    await entryDot.click();
    await page.waitForTimeout(800);

    // Switched to the creator's view for that date; scroll to the entries section
    await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight));
    await page.waitForTimeout(300);

    // The creator's entry should be visible (read-only button, disabled but present)
    // Use filter to allow disabled buttons
    const entryName = page.locator('button').filter({ hasText: ENTRY_NAME }).first();
    await entryName.scrollIntoViewIfNeeded({ timeout: 3000 }).catch(() => {});
    await expect(entryName).toBeVisible({ timeout: 10000 });

    // The time cell is the span right after the span wrapping the name button
    // (EntryList.tsx); neither carries a testid, so anchor on the name button.
    // Viewing a linked user shows the CREATOR's timezone: UTC 20:00 → LA 13:00
    // (12:00 outside DST), never the viewer's 20:00 UTC.
    const timeCell = entryName.locator('xpath=../following-sibling::span[1]');
    await expect(timeCell).toHaveText(/^1[23]:\d{2}$/, { timeout: 5000 });

    await ctx.close();
  });
});
