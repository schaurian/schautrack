import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, fetchMailpitMessages, extractCodeFromEmail, clearMailpit } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

// Generate a unique fake IP per test run so the server's in-memory rate limiter
// (5 req / 5 min per IP) never accumulates across repeated test runs.
// TRUST_PROXY=true (default) means the server reads X-Forwarded-For.
const runId = Math.floor(Math.random() * 200) + 10; // 10–209
const fakeIP = `10.255.${runId}.1`;
const extraHTTPHeaders = { 'X-Forwarded-For': fakeIP };

test.describe('Email Change', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('email-change');
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
      await page.waitForURL(new RegExp(path), { timeout: 10000 });
    }
  }

  test('change email triggers verification and email is sent', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, extraHTTPHeaders });
    const page = await ctx.newPage();

    await clearMailpit();
    await loginAndGo(page, '/settings');

    const newEmail = `change-test-${Date.now()}@test.local`;

    // Scroll to Change Email section
    const emailHeading = page.getByText('Change Email', { exact: true });
    await emailHeading.scrollIntoViewIfNeeded();

    // Fill new email and password — password field is right after the New Email input
    await page.getByLabel('New Email').fill(newEmail);
    // The email change form's password input follows "New Email" — use the form context
    const emailForm = page.locator('form').filter({ has: page.getByLabel('New Email') });
    await emailForm.locator('input[type="password"]').fill(user.password);

    // Submit the form
    await page.getByRole('button', { name: 'Send Verification Code' }).click();

    // Should navigate to the verify page
    await page.waitForURL(/\/settings\/email\/verify/, { timeout: 10000 });
    await expect(page.getByText('Verify New Email')).toBeVisible({ timeout: 5000 });

    // Verify an email was sent to the new address in MailPit
    let messages: Awaited<ReturnType<typeof fetchMailpitMessages>> = [];
    for (let i = 0; i < 10; i++) {
      messages = await fetchMailpitMessages(newEmail);
      if (messages.length > 0) break;
      await page.waitForTimeout(500);
    }
    expect(messages.length).toBeGreaterThan(0);
    expect(messages[0].To.some((t: { Address: string }) => t.Address === newEmail)).toBe(true);

    // Cancel so serial state is clean for next test
    await page.getByRole('button', { name: 'Cancel' }).click();
    await page.waitForURL(/\/settings$/, { timeout: 10000 });

    await ctx.close();
  });

  test('verify new email with code from MailPit', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, extraHTTPHeaders });
    const page = await ctx.newPage();

    // Clear MailPit, then start the change flow to get a fresh code
    await clearMailpit();
    await loginAndGo(page, '/settings');

    const newEmail = `verify-test-${Date.now()}@test.local`;
    const emailSection = page.getByText('Change Email').first();
    await emailSection.scrollIntoViewIfNeeded();

    await page.getByLabel('New Email').fill(newEmail);
    await page.locator('#new-email').locator('..').locator('..').locator('input[type="password"]').fill(user.password);
    await page.getByRole('button', { name: 'Send Verification Code' }).click();
    await page.waitForURL(/\/settings\/email\/verify/, { timeout: 10000 });

    // Extract the verification code from MailPit
    const code = await extractCodeFromEmail(newEmail, 30);
    expect(code).toMatch(/^\d{6}$/);

    // Enter the code on the verify page
    await page.getByLabel('Verification Code').fill(code);
    await page.getByRole('button', { name: 'Verify' }).click();

    // After successful verification, should redirect back to settings (not /settings/email/verify)
    await page.waitForURL(/\/settings$/, { timeout: 10000 });

    // The email should now be updated — verify via psql
    const updatedEmail = psql(`SELECT email FROM users WHERE email = '${newEmail}'`);
    expect(updatedEmail).toBe(newEmail);

    // Restore the original email so subsequent serial tests can log in with user.email
    psql(`UPDATE users SET email = '${user.email}' WHERE email = '${newEmail}'`);

    await ctx.close();
  });

  test('cancel pending email change', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, extraHTTPHeaders });
    const page = await ctx.newPage();

    await clearMailpit();
    await loginAndGo(page, '/settings');

    // Initiate an email change
    const newEmail = `cancel-test-${Date.now()}@test.local`;
    const emailSection = page.getByText('Change Email').first();
    await emailSection.scrollIntoViewIfNeeded();

    await page.getByLabel('New Email').fill(newEmail);
    await page.locator('#new-email').locator('..').locator('..').locator('input[type="password"]').fill(user.password);
    await page.getByRole('button', { name: 'Send Verification Code' }).click();
    await page.waitForURL(/\/settings\/email\/verify/, { timeout: 10000 });
    await expect(page.getByText('Verify New Email')).toBeVisible({ timeout: 5000 });

    // Cancel the pending change
    await page.getByRole('button', { name: 'Cancel' }).click();

    // Should redirect back to settings (not /settings/email/verify)
    await page.waitForURL(/\/settings$/, { timeout: 10000 });

    // The Change Email form should be visible again (no pending indicator blocking it)
    const emailSectionAfter = page.getByText('Change Email').first();
    await emailSectionAfter.scrollIntoViewIfNeeded();
    await expect(emailSectionAfter).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole('button', { name: 'Send Verification Code' })).toBeVisible({ timeout: 5000 });

    await ctx.close();
  });

  test('restore original email via psql to ensure clean state', async ({ browser }) => {
    // Defensive cleanup: restore isolated user email if any test left it changed
    psql(
      `UPDATE users SET email = '${user.email}' ` +
      `WHERE email LIKE 'change-test-%' OR email LIKE 'verify-test-%' OR email LIKE 'cancel-test-%'`
    );

    // Verify we can still navigate to settings as the isolated user
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] }, extraHTTPHeaders });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');
    await expect(page.getByText(user.email)).toBeVisible({ timeout: 5000 });

    await ctx.close();
  });
});
