import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let viewer: { email: string; password: string; id: string };
let owner: { email: string; password: string; id: string };

const TODAY = new Date().toLocaleDateString('en-CA', { timeZone: 'UTC' });

const TEST_NOTE_CONTENT = 'E2E linked-user note test';
const TEST_ENTRY_AMOUNT = 500;
const TEST_WEIGHT = 70.5;
const TEST_TODO_NAME = 'E2E linked-user todo';

test.describe('Linked User Data', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    viewer = createIsolatedUser('linked-data-viewer');
    owner = createIsolatedUser('linked-data-owner');

    // Enable todos and notes for the owner
    psql(`UPDATE users SET todos_enabled = true, notes_enabled = true WHERE id = ${owner.id}`);

    // Ensure an accepted link exists from viewer to owner
    psql(`
      INSERT INTO account_links (requester_id, target_id, status)
      VALUES (${viewer.id}, ${owner.id}, 'accepted')
      ON CONFLICT DO NOTHING
    `);

    // createIsolatedUser already cleaned data — insert fresh test data for the owner
    psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name) VALUES (${owner.id}, '${TODAY}', ${TEST_ENTRY_AMOUNT}, 'E2E test meal')`);
    psql(`INSERT INTO weight_entries (user_id, entry_date, weight) VALUES (${owner.id}, '${TODAY}', ${TEST_WEIGHT}) ON CONFLICT (user_id, entry_date) DO UPDATE SET weight = ${TEST_WEIGHT}`);
    psql(`INSERT INTO daily_notes (user_id, note_date, content) VALUES (${owner.id}, '${TODAY}', '${TEST_NOTE_CONTENT}') ON CONFLICT (user_id, note_date) DO UPDATE SET content = '${TEST_NOTE_CONTENT}'`);
    psql(`INSERT INTO todos (user_id, name, schedule) VALUES (${owner.id}, '${TEST_TODO_NAME}', '{"type":"daily"}') ON CONFLICT DO NOTHING`);
  });

  test.afterAll(() => {
    if (!viewer?.id || !owner?.id) return;
    psql(`DELETE FROM account_links WHERE (requester_id = ${viewer.id} AND target_id = ${owner.id}) OR (requester_id = ${owner.id} AND target_id = ${viewer.id})`);
  });

  /** Log in as the viewer and switch dashboard to the owner's data. */
  async function switchToOwner(page: import('@playwright/test').Page) {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(viewer.email);
    await page.getByLabel('Password').fill(viewer.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });

    const timeline = page.getByText('Timeline');
    await timeline.scrollIntoViewIfNeeded({ timeout: 5000 });

    // Find the label span for the owner's card, then find the card's today dot as a sibling
    // The ShareCard structure: .rounded-xl > div.mb-2 > span[label], followed by a div with dots
    const ownerLabel = page.locator('span.text-sm.font-medium').filter({ hasText: new RegExp(owner.email.split('@')[0], 'i') }).first();
    await expect(ownerLabel).toBeVisible({ timeout: 8000 });

    // The dots grid is a sibling div of the label's parent div, inside the same .rounded-xl
    // Navigate: span -> parent div.mb-2 -> parent .rounded-xl -> find the today dot
    const ownerCard = ownerLabel.locator('../..'); // span -> div.mb-2 -> .rounded-xl
    const todayDot = ownerCard.locator(`button[title="${TODAY}"]`);
    await expect(todayDot).toBeVisible({ timeout: 5000 });
    await todayDot.click();

    await page.waitForTimeout(500);
  }

  test('view linked user entries — read-only, no Track button', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await switchToOwner(page);

    const entries = page.locator('.rounded-xl').filter({ hasText: /Entries/ });
    await entries.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(entries).toBeVisible({ timeout: 5000 });
    await expect(entries.getByText('E2E test meal')).toBeVisible({ timeout: 5000 });
    await expect(entries.getByText(String(TEST_ENTRY_AMOUNT))).toBeVisible({ timeout: 5000 });

    const trackButton = page.getByRole('button', { name: 'Track' });
    await expect(trackButton).not.toBeVisible({ timeout: 3000 });

    const deleteButton = entries.getByRole('button', { name: /delete/i });
    await expect(deleteButton).not.toBeVisible({ timeout: 2000 });
    await ctx.close();
  });

  test('view linked user weight', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await switchToOwner(page);

    const weightSection = page.locator('.rounded-xl').filter({ hasText: /Weight/ });
    await weightSection.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(weightSection).toBeVisible({ timeout: 5000 });

    const weightDisplay = weightSection.locator('span').filter({ hasText: new RegExp(Number(TEST_WEIGHT).toFixed(1)) });
    await expect(weightDisplay.first()).toBeVisible({ timeout: 5000 });

    const deleteButton = weightSection.getByRole('button', { name: /delete/i });
    await expect(deleteButton).not.toBeVisible({ timeout: 2000 });
    await ctx.close();
  });

  test('view linked user todos', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await switchToOwner(page);

    const todosSection = page.locator('.rounded-xl').filter({ hasText: /Todos/ }).first();
    await todosSection.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(todosSection).toBeVisible({ timeout: 5000 });

    await expect(page.getByText(TEST_TODO_NAME).first()).toBeVisible({ timeout: 8000 });
    await ctx.close();
  });

  test('view linked user notes — visible but not editable', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await switchToOwner(page);

    const notesSection = page.locator('.rounded-xl').filter({ hasText: /Notes/ }).first();
    await notesSection.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(notesSection).toBeVisible({ timeout: 5000 });

    const textarea = notesSection.locator('textarea');
    await expect(textarea).toBeVisible({ timeout: 8000 });
    await expect(textarea).toHaveValue(TEST_NOTE_CONTENT, { timeout: 8000 });
    await expect(textarea).toBeDisabled();
    await ctx.close();
  });
});
