import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { psql, bcryptHash } from './fixtures/helpers';

const TEST_USER_EMAIL = 'test@test.com';
const LINK_USER_EMAIL = 'link-test@test.com';
const LINK_USER_PASSWORD = 'linktest1234';

let testUserId = '';
let linkUserId = '';

// Today's date string in YYYY-MM-DD (UTC)
const TODAY = new Date().toLocaleDateString('en-CA', { timeZone: 'UTC' });

const TEST_NOTE_CONTENT = 'E2E linked-user note test';
const TEST_ENTRY_AMOUNT = 500;
const TEST_WEIGHT = 70.5;
const TEST_TODO_NAME = 'E2E linked-user todo';

test.beforeAll(() => {
  // Resolve user IDs
  testUserId = psql(`SELECT id FROM users WHERE email = '${TEST_USER_EMAIL}'`);
  if (!testUserId) throw new Error(`Test user ${TEST_USER_EMAIL} not found — run setup-test-user first`);

  // Ensure link-test user exists
  const existing = psql(`SELECT id FROM users WHERE email = '${LINK_USER_EMAIL}'`);
  if (existing) {
    linkUserId = existing;
    const hash = bcryptHash(LINK_USER_PASSWORD);
    psql(`UPDATE users SET password_hash = '${hash}', email_verified = true WHERE id = ${linkUserId}`);
  } else {
    const hash = bcryptHash(LINK_USER_PASSWORD);
    psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${LINK_USER_EMAIL}', '${hash}', true)`);
    linkUserId = psql(`SELECT id FROM users WHERE email = '${LINK_USER_EMAIL}'`);
  }

  // Enable todos and notes for the link-test user
  psql(`UPDATE users SET todos_enabled = true, notes_enabled = true WHERE id = ${linkUserId}`);

  // Ensure an accepted link exists (both directions via a single row is fine — the app queries both)
  psql(`
    INSERT INTO account_links (requester_id, target_id, status)
    VALUES (${testUserId}, ${linkUserId}, 'accepted')
    ON CONFLICT DO NOTHING
  `);

  // Clean up any previous test data for the link user
  psql(`DELETE FROM calorie_entries WHERE user_id = ${linkUserId} AND entry_date = '${TODAY}'`);
  psql(`DELETE FROM weight_entries WHERE user_id = ${linkUserId} AND entry_date = '${TODAY}'`);
  psql(`DELETE FROM daily_notes WHERE user_id = ${linkUserId} AND note_date = '${TODAY}'`);
  psql(`DELETE FROM todos WHERE user_id = ${linkUserId} AND name = '${TEST_TODO_NAME}'`);

  // Insert test data for the link-test user
  psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name) VALUES (${linkUserId}, '${TODAY}', ${TEST_ENTRY_AMOUNT}, 'E2E test meal')`);
  psql(`INSERT INTO weight_entries (user_id, entry_date, weight) VALUES (${linkUserId}, '${TODAY}', ${TEST_WEIGHT})`);
  psql(`INSERT INTO daily_notes (user_id, note_date, content) VALUES (${linkUserId}, '${TODAY}', '${TEST_NOTE_CONTENT}')`);
  psql(`INSERT INTO todos (user_id, name, schedule) VALUES (${linkUserId}, '${TEST_TODO_NAME}', '{"type":"daily"}')`);
});

test.afterAll(() => {
  if (!linkUserId || !testUserId) return;

  // Remove the link
  psql(`DELETE FROM account_links WHERE (requester_id = ${testUserId} AND target_id = ${linkUserId}) OR (requester_id = ${linkUserId} AND target_id = ${testUserId})`);

  // Remove the test data inserted by this suite
  psql(`DELETE FROM calorie_entries WHERE user_id = ${linkUserId} AND entry_date = '${TODAY}'`);
  psql(`DELETE FROM weight_entries WHERE user_id = ${linkUserId} AND entry_date = '${TODAY}'`);
  psql(`DELETE FROM daily_notes WHERE user_id = ${linkUserId} AND note_date = '${TODAY}'`);
  psql(`DELETE FROM todos WHERE user_id = ${linkUserId} AND name = '${TEST_TODO_NAME}'`);
});

/** Switch the dashboard view to the linked user by clicking their share card dot for today. */
async function switchToLinkedUser(page: import('@playwright/test').Page) {
  await login(page);
  await page.goto('/dashboard');
  await page.waitForURL('/dashboard');

  // Scroll to Timeline section to find the linked user's card
  const timeline = page.getByText('Timeline');
  await timeline.scrollIntoViewIfNeeded({ timeout: 5000 });

  // Find the share card for the link-test user by their email label (or custom label)
  // The card label may be the email or a custom label set by a previous test
  const linkCard = page.locator('.rounded-xl').filter({ hasText: new RegExp(LINK_USER_EMAIL.split('@')[0], 'i') }).first();
  await expect(linkCard).toBeVisible({ timeout: 8000 });

  // Click the dot for today in the linked user's card
  const todayDot = linkCard.locator(`button[title="${TODAY}"]`);
  const hasTodayDot = await todayDot.isVisible({ timeout: 2000 }).catch(() => false);
  if (hasTodayDot) {
    await todayDot.click();
  } else {
    // Fall back to clicking the last dot in the card
    const dots = linkCard.locator('button[title]');
    const count = await dots.count();
    if (count > 0) await dots.nth(count - 1).click();
  }

  await page.waitForTimeout(500);
}

test('view linked user entries — read-only, no Track button', async ({ page }) => {
  await switchToLinkedUser(page);

  // The linked user's calorie entry should be visible in the Entries section
  const entries = page.locator('.rounded-xl').filter({ hasText: /Entries/ });
  await entries.scrollIntoViewIfNeeded({ timeout: 5000 });
  await expect(entries).toBeVisible({ timeout: 5000 });
  await expect(entries.getByText('E2E test meal')).toBeVisible({ timeout: 5000 });
  await expect(entries.getByText(String(TEST_ENTRY_AMOUNT))).toBeVisible({ timeout: 5000 });

  // Track button must NOT be present (read-only view)
  const trackButton = page.getByRole('button', { name: 'Track' });
  await expect(trackButton).not.toBeVisible({ timeout: 3000 });

  // Delete buttons must NOT be present in the entries list
  const deleteButton = entries.getByRole('button', { name: /delete/i });
  await expect(deleteButton).not.toBeVisible({ timeout: 2000 });
});

test('view linked user weight', async ({ page }) => {
  await switchToLinkedUser(page);

  // Weight section should show the linked user's weight value
  const weightSection = page.locator('.rounded-xl').filter({ hasText: /Weight/ });
  await weightSection.scrollIntoViewIfNeeded({ timeout: 5000 });
  await expect(weightSection).toBeVisible({ timeout: 5000 });

  // The weight value should be displayed as a read-only span (not an editable input)
  const weightDisplay = weightSection.locator('span').filter({ hasText: new RegExp(Number(TEST_WEIGHT).toFixed(1)) });
  await expect(weightDisplay.first()).toBeVisible({ timeout: 5000 });

  // No Delete button should be visible (can't edit linked user's weight)
  const deleteButton = weightSection.getByRole('button', { name: /delete/i });
  await expect(deleteButton).not.toBeVisible({ timeout: 2000 });
});

test('view linked user todos', async ({ page }) => {
  await switchToLinkedUser(page);

  // Todos section should be visible for the linked user (todos_enabled = true)
  const todosSection = page.locator('.rounded-xl').filter({ hasText: /Todos/ }).first();
  await todosSection.scrollIntoViewIfNeeded({ timeout: 5000 });
  await expect(todosSection).toBeVisible({ timeout: 5000 });

  // The linked user's todo should appear in the list
  await expect(page.getByText(TEST_TODO_NAME)).toBeVisible({ timeout: 8000 });
});

test('view linked user notes — visible but not editable', async ({ page }) => {
  await switchToLinkedUser(page);

  // Notes section should be visible for the linked user (notes_enabled = true)
  const notesSection = page.locator('.rounded-xl').filter({ hasText: /Notes/ }).first();
  await notesSection.scrollIntoViewIfNeeded({ timeout: 5000 });
  await expect(notesSection).toBeVisible({ timeout: 5000 });

  // The note content should be visible
  const textarea = notesSection.locator('textarea');
  await expect(textarea).toBeVisible({ timeout: 8000 });
  await expect(textarea).toHaveValue(TEST_NOTE_CONTENT, { timeout: 8000 });

  // The textarea must be disabled (canEdit=false for linked users)
  await expect(textarea).toBeDisabled();
});
