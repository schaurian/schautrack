import { test, expect } from '@playwright/test';
import { createHash } from 'crypto';
import { psql, bcryptHash, clearMailpit, extractCodeFromEmail } from './fixtures/helpers';

test.describe.configure({ mode: 'serial' });

const EMAIL = '2fa-reset@test.com';
const PASSWORD = '2fareset1234';
const TOTP_SECRET = 'JBSWY3DPEHPK3PXP';

let userId = '';

test.beforeAll(() => {
  // Ensure user exists with email_verified=true
  const hash = bcryptHash(PASSWORD);
  const existing = psql(`SELECT id FROM users WHERE email = '${EMAIL}'`);
  if (existing) {
    userId = existing;
    psql(`UPDATE users SET password_hash = '${hash}', email_verified = true WHERE id = ${userId}`);
  } else {
    psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${EMAIL}', '${hash}', true)`);
    userId = psql(`SELECT id FROM users WHERE email = '${EMAIL}'`);
  }

  // Enable 2FA with a known TOTP secret
  psql(`UPDATE users SET totp_enabled = true, totp_secret = '${TOTP_SECRET}' WHERE id = ${userId}`);

  // Clear any existing backup codes and insert a known one
  psql(`DELETE FROM totp_backup_codes WHERE user_id = ${userId}`);
  const codeHash = createHash('sha256').update('12345678').digest('hex');
  psql(`INSERT INTO totp_backup_codes (user_id, code_hash) VALUES (${userId}, '${codeHash}')`);
});

test.afterAll(() => {
  if (userId) {
    psql(`DELETE FROM users WHERE id = ${userId}`);
  }
});

test('login shows 2FA prompt', async ({ browser }) => {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();

  await page.goto('/login');
  await page.waitForLoadState('domcontentloaded');
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Log In' }).click();

  // Should see TOTP input — not redirect to dashboard
  const totpInput = page.getByPlaceholder(/enter 6-digit code/i);
  await expect(totpInput).toBeVisible({ timeout: 10000 });

  await context.close();
});

test('"Lost your authenticator?" link is clickable', async ({ browser }) => {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();

  await page.goto('/login');
  await page.waitForLoadState('domcontentloaded');
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Log In' }).click();

  // Wait for TOTP prompt
  await expect(page.getByPlaceholder(/enter 6-digit code/i)).toBeVisible({ timeout: 10000 });

  // "Lost your authenticator?" should be an interactive button (not a greyed-out span)
  const lostLink = page.getByRole('button', { name: /lost your authenticator/i });
  await expect(lostLink).toBeVisible({ timeout: 5000 });
  await expect(lostLink).toBeEnabled();

  await context.close();
});

test('reset 2FA via email code', async ({ browser }) => {
  await clearMailpit();

  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();

  // Log in to trigger TOTP prompt
  await page.goto('/login');
  await page.waitForLoadState('domcontentloaded');
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Log In' }).click();

  // Wait for TOTP prompt then click "Lost your authenticator?"
  await expect(page.getByPlaceholder(/enter 6-digit code/i)).toBeVisible({ timeout: 10000 });
  await page.getByRole('button', { name: /lost your authenticator/i }).click();

  // Reset request form: email and password fields should appear
  const resetEmailInput = page.getByLabel('Email');
  await expect(resetEmailInput).toBeVisible({ timeout: 5000 });
  // Fields may be pre-filled; ensure they contain correct values or fill them
  await resetEmailInput.fill(EMAIL);
  const resetPasswordInput = page.getByLabel('Password');
  await resetPasswordInput.fill(PASSWORD);

  await page.getByRole('button', { name: /send reset code/i }).click();

  // Extract 6-digit code from email
  const code = await extractCodeFromEmail(EMAIL, 20);
  expect(code).toMatch(/^\d{6}$/);

  // Enter the code
  const codeInput = page.getByLabel(/reset code|verification code/i).or(
    page.locator('input[maxlength="6"]')
  );
  await expect(codeInput).toBeVisible({ timeout: 5000 });
  await codeInput.fill(code);
  await page.getByRole('button', { name: /verify|submit|confirm/i }).click();

  // 2FA should now be disabled — user is either redirected to dashboard or shown a success message
  const isOnDashboard = page.waitForURL(/\/dashboard/, { timeout: 8000 }).then(() => true).catch(() => false);
  const hasSuccess = page.getByText(/2fa removed|2fa disabled|log in/i).isVisible({ timeout: 8000 }).catch(() => false);
  const [onDash, hasMsg] = await Promise.all([isOnDashboard, hasSuccess]);
  expect(onDash || hasMsg).toBe(true);

  await context.close();
});

test('login works without 2FA after reset', async ({ browser }) => {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();

  await page.goto('/login');
  await page.waitForLoadState('domcontentloaded');
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Log In' }).click();

  // Should go straight to dashboard — no TOTP prompt
  await page.waitForURL('/dashboard', { timeout: 15000 });
  await expect(page).toHaveURL(/\/dashboard/);

  // TOTP input must NOT be visible
  const totpInput = page.getByPlaceholder(/enter 6-digit code/i);
  await expect(totpInput).not.toBeVisible();

  await context.close();
});
