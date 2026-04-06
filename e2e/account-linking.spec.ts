import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { psql, bcryptHash } from './fixtures/helpers';

const TEST_USER_EMAIL = 'test@test.com';
const LINK_USER_EMAIL = 'link-test@test.com';
const LINK_USER_PASSWORD = 'linktest1234';

function ensureLinkUser() {
  const hash = bcryptHash(LINK_USER_PASSWORD);

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

  test.skip('send link request', async ({ page }) => {
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
    // Fresh context with NO cookies — must not inherit main user session
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/login');
    await page.waitForLoadState('domcontentloaded');
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

  test('decline link request', async ({ page }) => {
    // Clean up any existing links between the two test users first
    cleanupLinks();

    // Send a fresh link request from test user to link-test user
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    const emailInput = page.getByLabel('Link by email');
    await emailInput.scrollIntoViewIfNeeded();
    await emailInput.fill(LINK_USER_EMAIL);
    await page.getByRole('button', { name: 'Send', exact: true }).click();
    await expect(page.getByText('Pending')).toBeVisible({ timeout: 5000 });

    // Log in as link-test user in a fresh context and decline the request
    const context = await page.context().browser()!.newContext({ storageState: { cookies: [], origins: [] } });
    const linkPage = await context.newPage();

    await linkPage.goto('/login');
    await linkPage.waitForLoadState('domcontentloaded');
    await linkPage.getByLabel('Email').fill(LINK_USER_EMAIL);
    await linkPage.getByLabel('Password').fill(LINK_USER_PASSWORD);
    await linkPage.getByRole('button', { name: 'Log In' }).click();
    await linkPage.waitForURL('/dashboard', { timeout: 15000 });

    await linkPage.goto('/settings');
    await linkPage.waitForURL('/settings');

    // Verify the incoming request is visible
    const incomingHeading = linkPage.getByText('Incoming');
    await incomingHeading.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(incomingHeading).toBeVisible({ timeout: 5000 });
    await expect(linkPage.getByText(TEST_USER_EMAIL, { exact: true })).toBeVisible();

    // Decline it
    await linkPage.getByRole('button', { name: 'Decline' }).click();

    // The incoming request should disappear
    await expect(linkPage.getByText(TEST_USER_EMAIL, { exact: true })).not.toBeVisible({ timeout: 5000 });

    await context.close();

    // Log back in as test user and verify the link is no longer pending
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // The pending entry for LINK_USER_EMAIL should be gone
    await page.waitForTimeout(500);
    const pendingEntry = page.locator('div').filter({ hasText: LINK_USER_EMAIL }).filter({ has: page.getByText('Pending') });
    await expect(pendingEntry).not.toBeVisible({ timeout: 5000 });
  });

  test('max 3 links enforced', async ({ page }) => {
    // Create 3 dummy accepted links directly in DB
    const testUserId = psql(`SELECT id FROM users WHERE email = '${TEST_USER_EMAIL}'`);
    const dummyEmails = ['dummy1@test.com', 'dummy2@test.com', 'dummy3@test.com'];
    const hash = bcryptHash('dummy1234');

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
