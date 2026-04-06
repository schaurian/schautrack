import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { psql, fetchMailpitMessages, extractCodeFromEmail, clearMailpit } from './fixtures/helpers';

const TEST_USER_EMAIL = 'test@test.com';
const TEST_USER_PASSWORD = 'test1234test';

test.describe('Email Change', () => {
  test.describe.configure({ mode: 'serial' });

  test.skip('change email triggers verification and email is sent', async ({ page }) => {
    await clearMailpit();
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    const newEmail = `change-test-${Date.now()}@test.com`;

    // Scroll to Change Email section
    const emailHeading = page.getByText('Change Email', { exact: true });
    await emailHeading.scrollIntoViewIfNeeded();

    // Fill new email and password — password field is right after the New Email input
    await page.getByLabel('New Email').fill(newEmail);
    // The email change form's password input follows "New Email" — use the form context
    const emailForm = page.locator('form').filter({ has: page.getByLabel('New Email') });
    await emailForm.locator('input[type="password"]').fill(TEST_USER_PASSWORD);

    // Submit the form
    await page.getByRole('button', { name: 'Send Verification Code' }).click();

    // Should navigate to the verify page
    await page.waitForURL('/settings/email/verify', { timeout: 10000 });
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
  });

  test('verify new email with code from MailPit', async ({ page }) => {
    await login(page);

    // We need to initiate a fresh email change so we have a pending code in session.
    // First clear MailPit, then start the change flow again to get a fresh code.
    await clearMailpit();

    await page.goto('/settings');
    await page.waitForURL('/settings');

    const newEmail = `verify-test-${Date.now()}@test.com`;
    const emailSection = page.getByText('Change Email').first();
    await emailSection.scrollIntoViewIfNeeded();

    await page.getByLabel('New Email').fill(newEmail);
    await page.locator('#new-email').locator('..').locator('..').locator('input[type="password"]').fill(TEST_USER_PASSWORD);
    await page.getByRole('button', { name: 'Send Verification Code' }).click();
    await page.waitForURL('/settings/email/verify', { timeout: 10000 });

    // Extract the verification code from MailPit
    const code = await extractCodeFromEmail(newEmail, 15);
    expect(code).toMatch(/^\d{6}$/);

    // Enter the code on the verify page
    await page.getByLabel('Verification Code').fill(code);
    await page.getByRole('button', { name: 'Verify' }).click();

    // After successful verification, should redirect back to settings
    await page.waitForURL('/settings', { timeout: 10000 });

    // The email should now be updated — verify via psql
    const updatedEmail = psql(`SELECT email FROM users WHERE email = '${newEmail}'`);
    expect(updatedEmail).toBe(newEmail);

    // Restore the original email via psql so other tests are not affected
    psql(`UPDATE users SET email = '${TEST_USER_EMAIL}' WHERE email = '${newEmail}'`);
  });

  test('cancel pending email change', async ({ page }) => {
    await clearMailpit();
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Initiate an email change
    const newEmail = `cancel-test-${Date.now()}@test.com`;
    const emailSection = page.getByText('Change Email').first();
    await emailSection.scrollIntoViewIfNeeded();

    await page.getByLabel('New Email').fill(newEmail);
    await page.locator('#new-email').locator('..').locator('..').locator('input[type="password"]').fill(TEST_USER_PASSWORD);
    await page.getByRole('button', { name: 'Send Verification Code' }).click();
    await page.waitForURL('/settings/email/verify', { timeout: 10000 });
    await expect(page.getByText('Verify New Email')).toBeVisible({ timeout: 5000 });

    // Cancel the pending change
    await page.getByRole('button', { name: 'Cancel' }).click();

    // Should redirect back to settings
    await page.waitForURL('/settings', { timeout: 10000 });

    // The Change Email form should be visible again (no pending indicator blocking it)
    const emailSectionAfter = page.getByText('Change Email').first();
    await emailSectionAfter.scrollIntoViewIfNeeded();
    await expect(emailSectionAfter).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole('button', { name: 'Send Verification Code' })).toBeVisible({ timeout: 5000 });
  });

  test('restore original email via psql to ensure clean state', async ({ page }) => {
    // Defensive cleanup: if any prior test left the email changed, restore it.
    // Find any user whose email matches one of our test patterns (change-test-*, verify-test-*, cancel-test-*)
    // and restore their email back to the original test address.
    psql(
      `UPDATE users SET email = '${TEST_USER_EMAIL}' ` +
      `WHERE email LIKE 'change-test-%' OR email LIKE 'verify-test-%' OR email LIKE 'cancel-test-%'`
    );

    // Verify we can still navigate to settings as the original user
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');
    await expect(page.getByText(TEST_USER_EMAIL)).toBeVisible({ timeout: 5000 });
  });
});
