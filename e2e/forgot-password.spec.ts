import { test, expect } from '@playwright/test';
import { psql, bcryptHash, clearMailpit, extractCodeFromEmail } from './fixtures/helpers';

const FORGOT_EMAIL = 'forgot-test@test.com';
const FORGOT_PASSWORD_INITIAL = 'forgot1234test';
const FORGOT_PASSWORD_NEW = 'newpassword1234test';

test.describe('Forgot Password', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    // Ensure the test user exists with a known password
    const hash = bcryptHash(FORGOT_PASSWORD_INITIAL);
    const exists = psql(`SELECT id FROM users WHERE email = '${FORGOT_EMAIL}'`);
    if (exists) {
      psql(`UPDATE users SET password_hash = '${hash}', email_verified = true WHERE email = '${FORGOT_EMAIL}'`);
    } else {
      psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${FORGOT_EMAIL}', '${hash}', true)`);
    }
  });

  test.afterAll(() => {
    // Reset the password back to the initial value so this test is repeatable
    const hash = bcryptHash(FORGOT_PASSWORD_INITIAL);
    psql(`UPDATE users SET password_hash = '${hash}' WHERE email = '${FORGOT_EMAIL}'`);
  });

  test('full forgot password flow: request code → verify code → set new password → login', async ({ browser }) => {
    await clearMailpit();

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    // Step 1: go to forgot password page and submit email + captcha
    await page.goto('/forgot-password');
    await page.waitForLoadState('domcontentloaded');

    await page.getByLabel('Email').fill(FORGOT_EMAIL);

    // Wait for captcha to load, then fill it (CAPTCHA_BYPASS=true — any non-empty value passes)
    await expect(page.getByLabel('Captcha')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Captcha').fill('bypass');

    await page.getByRole('button', { name: 'Send Reset Code' }).click();

    // Should redirect to /reset-password
    await page.waitForURL(/\/reset-password/, { timeout: 10000 });
    await expect(page).toHaveURL(/\/reset-password/);

    // Step 2: extract code from email
    const code = await extractCodeFromEmail(FORGOT_EMAIL, 30);
    expect(code).toMatch(/^\d{6}$/);

    // Step 3: enter the code on the reset-password page
    await expect(page.getByLabel('Reset Code')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Reset Code').fill(code);
    await page.getByRole('button', { name: 'Verify Code' }).click();

    // Step 4: code verified — new password form should appear
    await expect(page.getByLabel('New Password')).toBeVisible({ timeout: 5000 });
    await expect(page.getByLabel('Confirm Password')).toBeVisible();

    await page.getByLabel('New Password').fill(FORGOT_PASSWORD_NEW);
    await page.getByLabel('Confirm Password').fill(FORGOT_PASSWORD_NEW);
    await page.getByRole('button', { name: 'Reset Password' }).click();

    // Step 5: success message and redirect to login
    await expect(page.getByText(/password updated/i)).toBeVisible({ timeout: 5000 });
    await page.waitForURL(/\/login/, { timeout: 5000 });
    await expect(page).toHaveURL(/\/login/);

    // Step 6: login with new password
    await page.getByLabel('Email').fill(FORGOT_EMAIL);
    await page.getByLabel('Password').fill(FORGOT_PASSWORD_NEW);
    await page.getByRole('button', { name: 'Log In' }).click();

    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    await expect(page).toHaveURL(/\/dashboard/);

    await context.close();
  });

  test('wrong reset code shows error', async ({ browser }) => {
    await clearMailpit();

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    // Submit forgot password to get to /reset-password
    await page.goto('/forgot-password');
    await page.waitForLoadState('domcontentloaded');

    await page.getByLabel('Email').fill(FORGOT_EMAIL);
    await expect(page.getByLabel('Captcha')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Captcha').fill('bypass');
    await page.getByRole('button', { name: 'Send Reset Code' }).click();

    await page.waitForURL(/\/reset-password/, { timeout: 10000 });

    // Enter a wrong code
    await expect(page.getByLabel('Reset Code')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Reset Code').fill('000000');
    await page.getByRole('button', { name: 'Verify Code' }).click();

    // Should show an error and stay on reset-password page
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL(/\/reset-password/);

    await context.close();
  });

  test('new password mismatch shows error', async ({ browser }) => {
    await clearMailpit();

    const mismatchEmail = `mismatch-pwd-${Date.now()}@test.com`;
    const hash = bcryptHash(FORGOT_PASSWORD_INITIAL);
    psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${mismatchEmail}', '${hash}', true)`);

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    // Request a reset code
    await page.goto('/forgot-password');
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(mismatchEmail);
    await expect(page.getByLabel('Captcha')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('Captcha').fill('bypass');
    await page.getByRole('button', { name: 'Send Reset Code' }).click();

    await page.waitForURL(/\/reset-password/, { timeout: 10000 });

    const code = await extractCodeFromEmail(mismatchEmail, 30);
    await page.getByLabel('Reset Code').fill(code);
    await page.getByRole('button', { name: 'Verify Code' }).click();

    // Now enter mismatched passwords
    await expect(page.getByLabel('New Password')).toBeVisible({ timeout: 5000 });
    await page.getByLabel('New Password').fill('correctpassword1234');
    await page.getByLabel('Confirm Password').fill('differentpassword1234');
    await page.getByRole('button', { name: 'Reset Password' }).click();

    // Should show an error
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL(/\/reset-password/);

    // Cleanup
    psql(`DELETE FROM users WHERE email = '${mismatchEmail}'`);

    await context.close();
  });

  test('cannot login with old password after reset', async ({ browser }) => {
    // After afterAll runs the password is reset, but within the serial suite
    // the new password is set. Verify old password fails here.
    // (This test runs BEFORE afterAll, so new password is active.)
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/login');
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(FORGOT_EMAIL);
    await page.getByLabel('Password').fill(FORGOT_PASSWORD_INITIAL);
    await page.getByRole('button', { name: 'Log In' }).click();

    // Should fail — password was changed in the first test
    await expect(page.getByRole('alert')).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL(/\/login/);

    await context.close();
  });
});
