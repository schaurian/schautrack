import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
const TODAY = new Date().toLocaleDateString('en-CA', { timeZone: 'UTC' });

let viewer: { email: string; password: string; id: string };
let owner: { email: string; password: string; id: string };

const TODO_NAME = 'E2E share-toggle todo';
const NOTE = 'E2E share-toggle note';

test.describe('Granular link sharing', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    viewer = createIsolatedUser('share-toggle-viewer');
    owner = createIsolatedUser('share-toggle-owner');
    psql(`UPDATE users SET todos_enabled = true, notes_enabled = true WHERE id = ${owner.id}`);
    // Link viewer -> owner (owner is target_id, so owner's outgoing map is target_shares).
    psql(`INSERT INTO account_links (requester_id, target_id, status)
          VALUES (${viewer.id}, ${owner.id}, 'accepted') ON CONFLICT DO NOTHING`);
    psql(`INSERT INTO daily_notes (user_id, note_date, content) VALUES (${owner.id}, '${TODAY}', '${NOTE}')
          ON CONFLICT (user_id, note_date) DO UPDATE SET content = '${NOTE}'`);
    psql(`INSERT INTO todos (user_id, name, schedule) VALUES (${owner.id}, '${TODO_NAME}', '{"type":"daily"}')
          ON CONFLICT DO NOTHING`);
  });

  test.afterAll(() => {
    if (!viewer?.id || !owner?.id) return;
    psql(`DELETE FROM account_links WHERE (requester_id = ${viewer.id} AND target_id = ${owner.id})
          OR (requester_id = ${owner.id} AND target_id = ${viewer.id})`);
  });

  function setOwnerShares(shares: Record<string, boolean>) {
    // Owner is target_id -> set target_shares.
    psql(`UPDATE account_links SET target_shares = '${JSON.stringify(shares)}'::jsonb
          WHERE requester_id = ${viewer.id} AND target_id = ${owner.id}`);
  }

  async function loginViewer(page: import('@playwright/test').Page) {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(viewer.email);
    await page.getByLabel('Password').fill(viewer.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
  }

  // Returns the owner's ShareCard label locator (absent when nothing is shared).
  function ownerCard(page: import('@playwright/test').Page) {
    return page.locator('.text-sm.font-medium')
      .filter({ hasText: new RegExp(owner.email.split('@')[0], 'i') }).first();
  }

  test('default off: owner card is absent (nothing shared)', async ({ browser }) => {
    setOwnerShares({ nutrition: false, weight: false, todos: false, notes: false });
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginViewer(page);
    await page.getByText('Timeline').scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(ownerCard(page)).toHaveCount(0, { timeout: 5000 });
    await ctx.close();
  });

  test('todos only: viewer sees the todo but not the note', async ({ browser }) => {
    setOwnerShares({ nutrition: false, weight: false, todos: true, notes: false });
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginViewer(page);
    await page.getByText('Timeline').scrollIntoViewIfNeeded({ timeout: 5000 });
    const card = ownerCard(page);
    await expect(card).toBeVisible({ timeout: 8000 });
    // Switch to the owner: click the card (its today dot, or the card itself).
    const cardRoot = card.locator('../..');
    const dot = cardRoot.locator(`button[title="${TODAY}"]`);
    if (await dot.count()) { await dot.click(); } else { await card.click(); }
    await page.waitForTimeout(500);
    await expect(page.getByText(TODO_NAME).first()).toBeVisible({ timeout: 8000 });
    await expect(page.getByText(NOTE)).toHaveCount(0, { timeout: 3000 });
    await ctx.close();
  });

  test('notes toggle persists via the settings UI', async ({ browser }) => {
    setOwnerShares({ nutrition: false, weight: false, todos: false, notes: false });
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    // Log in as the OWNER and toggle "Daily notes" on for the viewer link.
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(owner.email);
    await page.getByLabel('Password').fill(owner.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    await page.goto(`${baseURL}/settings`);
    await page.waitForLoadState('domcontentloaded');
    // The label wraps the checkbox — clicking the label text toggles it.
    const notesLabel = page.locator('label', { hasText: 'Daily notes' }).first();
    await notesLabel.scrollIntoViewIfNeeded({ timeout: 5000 });
    await notesLabel.click();
    // Assert it persisted server-side.
    await expect.poll(() =>
      psql(`SELECT target_shares->>'notes' FROM account_links WHERE requester_id = ${viewer.id} AND target_id = ${owner.id}`).trim(),
      { timeout: 5000 }
    ).toBe('true');
    await ctx.close();
  });
});
