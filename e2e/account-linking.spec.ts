import { test, expect } from '@playwright/test';
import { psql, bcryptHash, createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };
let linkUser: { email: string; password: string; id: string };

function cleanupLinks() {
  if (!user?.id || !linkUser?.id) return;
  psql(`DELETE FROM account_links WHERE (requester_id = ${user.id} AND target_id = ${linkUser.id}) OR (requester_id = ${linkUser.id} AND target_id = ${user.id})`);
}

test.describe('Account Linking', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('linking');
    linkUser = createIsolatedUser('linking-target');
    cleanupLinks();
    // Clean up dummy links from max-links test (from previous runs)
    for (const email of ['dummy1@test.local', 'dummy2@test.local', 'dummy3@test.local']) {
      const dummyId = psql(`SELECT id FROM users WHERE email = '${email}'`);
      if (dummyId && user.id) {
        psql(`DELETE FROM account_links WHERE (requester_id = ${user.id} AND target_id = ${dummyId}) OR (requester_id = ${dummyId} AND target_id = ${user.id})`);
      }
    }
  });

  async function loginAndGo(page: import('@playwright/test').Page, path = '/dashboard') {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    if (path !== '/dashboard') {
      await page.goto(`${baseURL}${path}`);
      await page.waitForURL(new RegExp(path.replace('/', '\\/')), { timeout: 10000 });
    }
  }

  async function loginAsLinkUser(browser: import('@playwright/test').Browser) {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(linkUser.email);
    await page.getByLabel('Password').fill(linkUser.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    return { ctx, page };
  }

  test('send link request', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    const emailInput = page.getByLabel('Link by email');
    await emailInput.scrollIntoViewIfNeeded();
    await emailInput.fill(linkUser.email);
    await page.getByRole('button', { name: 'Send Request' }).click();

    await expect(page.getByText('Pending')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(linkUser.email)).toBeVisible();
    await ctx.close();
  });

  test('accept link request from other user', async ({ browser }) => {
    const { ctx, page } = await loginAsLinkUser(browser);

    await page.goto(`${baseURL}/settings`);
    await page.waitForURL(/\/settings/, { timeout: 10000 });

    const incomingHeading = page.getByText('Incoming');
    await incomingHeading.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(incomingHeading).toBeVisible({ timeout: 5000 });
    await expect(page.getByText(user.email, { exact: true })).toBeVisible();

    await page.getByRole('button', { name: 'Accept' }).click();
    await expect(page.getByText('Linked')).toBeVisible({ timeout: 5000 });

    await ctx.close();
  });

  test('view linked user data on dashboard', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/dashboard');

    const linkUserCard = page.getByText(linkUser.email).or(page.getByText(linkUser.email.split('@')[0]));
    await expect(linkUserCard.first()).toBeVisible({ timeout: 5000 });
    await ctx.close();
  });

  test('set custom label on linked user', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    const linkedHeading = page.getByText('Linked');
    await linkedHeading.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(linkedHeading).toBeVisible({ timeout: 5000 });

    const userButton = page.locator('button').filter({ hasText: linkUser.email });
    await userButton.first().click();

    const labelInput = page.locator('input[autoFocus]').or(page.locator('input:focus'));
    await labelInput.first().fill('My Test Partner');
    await labelInput.first().press('Enter');

    await page.waitForTimeout(500);
    await page.reload();
    await page.waitForURL(/\/settings/, { timeout: 10000 });
    await expect(page.getByText('My Test Partner')).toBeVisible({ timeout: 5000 });
    await ctx.close();
  });

  test('linked user entries are read-only', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/dashboard');

    const partnerLabel = page.getByText('My Test Partner');
    await partnerLabel.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(partnerLabel).toBeVisible({ timeout: 5000 });

    const partnerCard = partnerLabel.locator('..').locator('..');
    const partnerDot = partnerCard.locator('button[title]').first();
    await partnerDot.click();
    await page.waitForTimeout(500);

    await page.evaluate(() => window.scrollTo(0, 0));
    const trackButton = page.getByRole('button', { name: 'Track' });
    await expect(trackButton).not.toBeVisible({ timeout: 3000 });
    await ctx.close();
  });

  test('remove link', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    const removeButton = page.getByRole('button', { name: 'Remove' });
    await removeButton.scrollIntoViewIfNeeded({ timeout: 5000 });
    await removeButton.click();
    await page.waitForTimeout(500);

    await expect(page.getByText('My Test Partner')).not.toBeVisible({ timeout: 5000 });
    await ctx.close();
  });

  test('decline link request', async ({ browser }) => {
    cleanupLinks();

    // Send a fresh link request from main user to link user
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    const emailInput = page.getByLabel('Link by email');
    await emailInput.scrollIntoViewIfNeeded();
    await emailInput.fill(linkUser.email);
    await page.getByRole('button', { name: 'Send Request' }).click();
    await expect(page.getByText('Pending')).toBeVisible({ timeout: 5000 });

    // Log in as link user and decline
    const { ctx: linkCtx, page: linkPage } = await loginAsLinkUser(browser);

    await linkPage.goto(`${baseURL}/settings`);
    await linkPage.waitForURL(/\/settings/, { timeout: 10000 });

    const incomingHeading = linkPage.getByText('Incoming');
    await incomingHeading.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(incomingHeading).toBeVisible({ timeout: 5000 });
    await expect(linkPage.getByText(user.email, { exact: true })).toBeVisible();

    await linkPage.getByRole('button', { name: 'Decline' }).click();
    await expect(linkPage.getByText(user.email, { exact: true })).not.toBeVisible({ timeout: 5000 });

    await linkCtx.close();

    // Verify from main user's side that it's no longer pending
    await page.reload();
    await page.waitForURL(/\/settings/, { timeout: 10000 });
    await page.waitForTimeout(500);
    const pendingEntry = page.locator('div').filter({ hasText: linkUser.email }).filter({ has: page.getByText('Pending') });
    await expect(pendingEntry).not.toBeVisible({ timeout: 5000 });

    await ctx.close();
  });

  test('max 3 links enforced', async ({ browser }) => {
    // Create 3 dummy accepted links directly in DB
    const dummyEmails = ['dummy1@test.local', 'dummy2@test.local', 'dummy3@test.local'];
    const hash = bcryptHash('dummy1234');

    for (const email of dummyEmails) {
      const exists = psql(`SELECT id FROM users WHERE email = '${email}'`);
      if (!exists) {
        psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${email}', '${hash}', true)`);
      }
      const dummyId = psql(`SELECT id FROM users WHERE email = '${email}'`);
      const linkExists = psql(`SELECT id FROM account_links WHERE requester_id = ${user.id} AND target_id = ${dummyId} AND status = 'accepted'`);
      if (!linkExists) {
        psql(`INSERT INTO account_links (requester_id, target_id, status) VALUES (${user.id}, ${dummyId}, 'accepted')`);
      }
    }

    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    const emailInput = page.getByLabel('Link by email');
    await expect(emailInput).not.toBeVisible({ timeout: 5000 });

    // Cleanup: remove the dummy links
    for (const email of dummyEmails) {
      const dummyId = psql(`SELECT id FROM users WHERE email = '${email}'`);
      psql(`DELETE FROM account_links WHERE (requester_id = ${user.id} AND target_id = ${dummyId}) OR (requester_id = ${dummyId} AND target_id = ${user.id})`);
    }

    await ctx.close();
  });
});
