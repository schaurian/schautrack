import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { execSync } from 'child_process';

const DB_CONTAINER = process.env.DB_CONTAINER || 'schautrack-test-db-1';
const DB_USER = process.env.POSTGRES_USER || 'schautrack';
const DB_NAME = process.env.POSTGRES_DB || 'schautrack';

const TEST_USER_EMAIL = 'test@test.com';
const LINK_USER_EMAIL = 'link-test@test.com';
const LINK_USER_PASSWORD = 'linktest1234';

function psql(sql: string): string {
  return execSync(
    `docker exec -i ${DB_CONTAINER} psql -U ${DB_USER} -d ${DB_NAME} -tA`,
    { input: sql + '\n', encoding: 'utf-8' }
  ).trim();
}

function ensureLinkUser() {
  const hash = execSync(
    `python3 -c "import bcrypt; print(bcrypt.hashpw(b'${LINK_USER_PASSWORD}', bcrypt.gensalt(10)).decode())"`,
    { encoding: 'utf-8' }
  ).trim();

  const exists = psql(`SELECT id FROM users WHERE email = '${LINK_USER_EMAIL}'`);
  if (exists) {
    psql(`UPDATE users SET password_hash = '${hash}', email_verified = true WHERE email = '${LINK_USER_EMAIL}'`);
  } else {
    psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${LINK_USER_EMAIL}', '${hash}', true)`);
  }
}

function cleanupLinks() {
  const testUserId = psql(`SELECT id FROM users WHERE email = '${TEST_USER_EMAIL}'`);
  const linkUserId = psql(`SELECT id FROM users WHERE email = '${LINK_USER_EMAIL}'`);
  if (testUserId && linkUserId) {
    psql(`DELETE FROM account_links WHERE (requester_id = ${testUserId} AND target_id = ${linkUserId}) OR (requester_id = ${linkUserId} AND target_id = ${testUserId})`);
  }
}

test.describe('Account Linking', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    ensureLinkUser();
    cleanupLinks();
    // Clean up dummy links from max-links test (from previous runs)
    const testUserId = psql(`SELECT id FROM users WHERE email = '${TEST_USER_EMAIL}'`);
    for (const email of ['dummy1@test.com', 'dummy2@test.com', 'dummy3@test.com']) {
      const dummyId = psql(`SELECT id FROM users WHERE email = '${email}'`);
      if (dummyId && testUserId) {
        psql(`DELETE FROM account_links WHERE (requester_id = ${testUserId} AND target_id = ${dummyId}) OR (requester_id = ${dummyId} AND target_id = ${testUserId})`);
      }
    }
  });

  // No afterAll cleanup — beforeAll handles it on next run.
  // Cleaning here would break dependent sequential tests when run as a subset.

  test('send link request', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Use the specific "Link by email" input
    const emailInput = page.getByLabel('Link by email');
    await emailInput.scrollIntoViewIfNeeded();
    await emailInput.fill(LINK_USER_EMAIL);
    await page.getByRole('button', { name: 'Send', exact: true }).click();

    // Should show as pending
    await expect(page.getByText('Pending')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(LINK_USER_EMAIL)).toBeVisible();
  });

  test('accept link request from other user', async ({ browser }) => {
    const context = await browser.newContext();
    const page = await context.newPage();

    await page.goto('/login');
    await page.getByLabel('Email').fill(LINK_USER_EMAIL);
    await page.getByLabel('Password').fill(LINK_USER_PASSWORD);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL('/dashboard', { timeout: 15000 });

    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Should see incoming request
    const incomingHeading = page.getByText('Incoming');
    await incomingHeading.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(incomingHeading).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(TEST_USER_EMAIL, { exact: true })).toBeVisible();

    // Accept it
    await page.getByRole('button', { name: 'Accept' }).click();

    // Should now show as linked
    await expect(page.getByText('Linked')).toBeVisible({ timeout: 5000 });

    await context.close();
  });

  test('view linked user data on dashboard', async ({ page }) => {
    await login(page);
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    // Should see a share card for the linked user (email or username)
    const linkUserCard = page.getByText(LINK_USER_EMAIL).or(page.getByText('link-test'));
    await expect(linkUserCard.first()).toBeVisible({ timeout: 5000 });
  });

  test('set custom label on linked user', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Find the linked section and the user's name button
    const linkedHeading = page.getByText('Linked');
    await linkedHeading.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(linkedHeading).toBeVisible({ timeout: 5000 });

    // Click the linked user's email to start editing label
    const userButton = page.locator('button').filter({ hasText: LINK_USER_EMAIL });
    await userButton.first().click();

    // Type a custom label in the input that appears
    const labelInput = page.locator('input[autoFocus]').or(page.locator('input:focus'));
    await labelInput.first().fill('My Test Partner');
    await labelInput.first().press('Enter');

    // Verify the label persists after reload
    await page.waitForTimeout(500);
    await page.reload();
    await page.waitForURL('/settings');
    await expect(page.getByText('My Test Partner')).toBeVisible({ timeout: 5000 });
  });

  test('linked user entries are read-only', async ({ page }) => {
    await login(page);
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    // Scroll down to the Timeline section where share cards live
    const partnerLabel = page.getByText('My Test Partner');
    await partnerLabel.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(partnerLabel).toBeVisible({ timeout: 5000 });

    // Click a dot in the partner's share card to switch to their view
    // Go up to the card root (label -> label-row div -> card div) then find dots
    const partnerCard = partnerLabel.locator('..').locator('..');
    const partnerDot = partnerCard.locator('button[title]').first();
    await partnerDot.click();
    await page.waitForTimeout(500);

    // Scroll to top — entry form should not be visible for linked user
    await page.evaluate(() => window.scrollTo(0, 0));
    const trackButton = page.getByRole('button', { name: 'Track' });
    await expect(trackButton).not.toBeVisible({ timeout: 3000 });
  });

  test('remove link', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Scroll to the Remove button in Account Links
    const removeButton = page.getByRole('button', { name: 'Remove' });
    await removeButton.scrollIntoViewIfNeeded({ timeout: 5000 });
    await removeButton.click();
    await page.waitForTimeout(500);

    // The linked user should no longer appear
    await expect(page.getByText('My Test Partner')).not.toBeVisible({ timeout: 5000 });
  });

  test('max 3 links enforced', async ({ page }) => {
    // Create 3 dummy accepted links directly in DB
    const testUserId = psql(`SELECT id FROM users WHERE email = '${TEST_USER_EMAIL}'`);
    const dummyEmails = ['dummy1@test.com', 'dummy2@test.com', 'dummy3@test.com'];
    const hash = execSync(
      `python3 -c "import bcrypt; print(bcrypt.hashpw(b'dummy1234', bcrypt.gensalt(10)).decode())"`,
      { encoding: 'utf-8' }
    ).trim();

    for (const email of dummyEmails) {
      const exists = psql(`SELECT id FROM users WHERE email = '${email}'`);
      if (!exists) {
        psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${email}', '${hash}', true)`);
      }
      const dummyId = psql(`SELECT id FROM users WHERE email = '${email}'`);
      const linkExists = psql(`SELECT id FROM account_links WHERE requester_id = ${testUserId} AND target_id = ${dummyId} AND status = 'accepted'`);
      if (!linkExists) {
        psql(`INSERT INTO account_links (requester_id, target_id, status) VALUES (${testUserId}, ${dummyId}, 'accepted')`);
      }
    }

    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // The "Link by email" input should not be visible (no slots left)
    const emailInput = page.getByLabel('Link by email');
    await expect(emailInput).not.toBeVisible({ timeout: 5000 });

    // Cleanup: remove the dummy links
    for (const email of dummyEmails) {
      const dummyId = psql(`SELECT id FROM users WHERE email = '${email}'`);
      psql(`DELETE FROM account_links WHERE (requester_id = ${testUserId} AND target_id = ${dummyId}) OR (requester_id = ${dummyId} AND target_id = ${testUserId})`);
    }
  });
});
