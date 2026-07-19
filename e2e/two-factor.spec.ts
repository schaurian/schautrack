import { test, expect } from '@playwright/test';
import { psql, generateTOTP, bcryptHash, expireStepUpGrace } from './fixtures/helpers';
import { completeStepUp } from './fixtures/stepup';

test.describe.configure({ mode: 'serial' });

const EMAIL = '2fa@test.com';
const PASSWORD = '2fa1234test';

let twoFaUserId = '';

let capturedSecret = '';
let capturedBackupCodes: string[] = [];

async function loginAs2faUser(page: import('@playwright/test').Page) {
  await page.goto('/login');
  await page.waitForLoadState('domcontentloaded');
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Log In' }).click();
}

async function logout(page: import('@playwright/test').Page) {
  // getByRole respects visibility — avoids matching the hidden mobile-only
  // logout row on /settings (getByText would strict-mode-fail there).
  await page.getByRole('button', { name: 'Logout' }).click();
  await page.waitForURL(/\/login|\//, { timeout: 10000 });
}

test.describe('Two-Factor Authentication', () => {
  test.beforeAll(() => {
    // Reset 2FA state for the test user before the suite runs
    const hash = bcryptHash(PASSWORD);
    twoFaUserId = psql(`SELECT id FROM users WHERE email = '${EMAIL}'`);
    if (twoFaUserId) {
      psql(`UPDATE users SET password_hash = '${hash}', totp_enabled = false, totp_secret = NULL WHERE id = ${twoFaUserId}`);
      psql(`DELETE FROM totp_backup_codes WHERE user_id = ${twoFaUserId}`);
    }
  });

  test('1. Enable 2FA', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await loginAs2faUser(page);
    await page.waitForURL('/dashboard', { timeout: 15000 });

    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Intercept the setup API to capture the secret
    let setupData: any = null;
    await page.route('**/2fa/setup', async (route) => {
      const response = await route.fetch();
      setupData = await response.json();
      await route.fulfill({ response });
    });

    // Find and click the Setup 2FA button
    const setup2faBtn = page.getByRole('button', { name: /setup 2fa/i });
    await setup2faBtn.scrollIntoViewIfNeeded();
    await expect(setup2faBtn).toBeVisible({ timeout: 10000 });
    await setup2faBtn.click();

    // Wait for the QR code to appear (means API responded)
    await expect(page.locator('img[alt="2FA QR Code"]')).toBeVisible({ timeout: 10000 });
    expect(setupData).toBeTruthy();
    expect(setupData.secret).toBeTruthy();
    capturedSecret = setupData.secret;

    // Generate a TOTP code and fill in the verification input
    const totpCode = generateTOTP(capturedSecret);
    const verificationInput = page.getByPlaceholder(/6-digit|verification code/i).or(
      page.getByLabel(/verification code/i)
    );
    await expect(verificationInput).toBeVisible({ timeout: 10000 });
    await verificationInput.fill(totpCode);

    // Intercept enable response to capture backup codes
    let enableData: any = null;
    await page.route('**/2fa/enable', async (route) => {
      const response = await route.fetch();
      enableData = await response.json();
      await route.fulfill({ response });
    });

    // Click Activate button
    const activateBtn = page.getByRole('button', { name: /activate/i });
    await expect(activateBtn).toBeVisible({ timeout: 5000 });
    await activateBtn.click();

    // Wait for backup codes to appear
    await expect(page.getByText('Backup Codes', { exact: true })).toBeVisible({ timeout: 10000 });
    expect(enableData).toBeTruthy();
    expect(enableData.backupCodes).toHaveLength(8);
    capturedBackupCodes = enableData.backupCodes;

    // Verify backup codes are displayed on the page
    for (const code of capturedBackupCodes) {
      await expect(page.getByText(code)).toBeVisible({ timeout: 10000 });
    }

    await context.close();
  });

  test('2. Log out and log back in with TOTP', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    // Start from settings (already logged in from previous test — need fresh login)
    await loginAs2faUser(page);

    // Should see TOTP prompt (not redirect to dashboard yet)
    const totpInput = page.getByLabel('2FA Code');
    await expect(totpInput).toBeVisible({ timeout: 10000 });

    // Generate code and verify
    const totpCode = generateTOTP(capturedSecret);
    await totpInput.fill(totpCode);
    await page.getByRole('button', { name: /verify/i }).click();

    await page.waitForURL('/dashboard', { timeout: 15000 });
    await expect(page).toHaveURL(/\/dashboard/);

    await logout(page);
    await context.close();
  });

  test('3. Log in with backup code', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await loginAs2faUser(page);

    // Should see 2FA prompt — same input accepts both TOTP and backup codes
    const codeInput = page.getByLabel('2FA Code');
    await expect(codeInput).toBeVisible({ timeout: 10000 });

    // Enter a backup code (the login page accepts it in the same field)
    expect(capturedBackupCodes.length).toBeGreaterThan(0);
    const backupCodeToUse = capturedBackupCodes[0];
    await codeInput.fill(backupCodeToUse);

    await page.getByRole('button', { name: /verify/i }).click();

    await page.waitForURL('/dashboard', { timeout: 15000 });
    await expect(page).toHaveURL(/\/dashboard/);

    await logout(page);
    await context.close();
  });

  test('4. Regenerate backup codes', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    // Login with TOTP
    await loginAs2faUser(page);
    const totpInput = page.getByLabel('2FA Code');
    await expect(totpInput).toBeVisible({ timeout: 10000 });
    await totpInput.fill(generateTOTP(capturedSecret));
    await page.getByRole('button', { name: /verify/i }).click();
    await page.waitForURL('/dashboard', { timeout: 15000 });

    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Expire the step-up grace server-side (deterministic) so the action is gated.
    expireStepUpGrace(twoFaUserId);

    // Intercept regenerate response — set up before triggering the action so
    // the retry after step-up is captured too.
    let regenData: any = null;
    await page.route('**/2fa/backup-codes', async (route) => {
      const response = await route.fetch();
      const body = await response.text();
      try { regenData = JSON.parse(body); } catch { /* not JSON */ }
      await route.fulfill({ response, body });
    });

    // Click regenerate — step-up modal gates this; password+TOTP needed.
    const regenBtn = page.getByText(/regenerate backup codes/i);
    await regenBtn.scrollIntoViewIfNeeded();
    await expect(regenBtn).toBeVisible({ timeout: 10000 });
    await regenBtn.click();
    await completeStepUp(page, PASSWORD, generateTOTP(capturedSecret));

    // Wait for new codes to appear
    await expect(page.getByText('Backup Codes', { exact: true })).toBeVisible({ timeout: 10000 });
    expect(regenData).toBeTruthy();
    expect(regenData.backupCodes).toHaveLength(8);

    // Update captured backup codes
    capturedBackupCodes = regenData.backupCodes;

    // Verify new codes are displayed
    for (const code of capturedBackupCodes) {
      await expect(page.getByText(code)).toBeVisible({ timeout: 10000 });
    }

    await context.close();
  });

  test('5. Disable 2FA', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    // Login with TOTP
    await loginAs2faUser(page);
    const totpInput = page.getByLabel('2FA Code');
    await expect(totpInput).toBeVisible({ timeout: 10000 });
    await totpInput.fill(generateTOTP(capturedSecret));
    await page.getByRole('button', { name: /verify/i }).click();
    await page.waitForURL('/dashboard', { timeout: 15000 });

    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Expire the step-up grace server-side so the disable is gated.
    expireStepUpGrace(twoFaUserId);

    // The 2FA card now just shows the "Disable 2FA" button — re-auth happens
    // in the step-up modal.
    const disableBtn = page.getByRole('button', { name: /disable 2fa/i });
    await disableBtn.scrollIntoViewIfNeeded();
    await expect(disableBtn).toBeVisible({ timeout: 10000 });
    await disableBtn.click();
    await completeStepUp(page, PASSWORD, generateTOTP(capturedSecret));

    // Wait for the Setup 2FA button to reappear (means 2FA was disabled)
    await expect(page.getByRole('button', { name: /setup 2fa/i })).toBeVisible({ timeout: 10000 });

    await context.close();
  });

  test('6. Login works without 2FA after disable', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await loginAs2faUser(page);

    // Should go straight to dashboard — no TOTP prompt
    await page.waitForURL('/dashboard', { timeout: 15000 });
    await expect(page).toHaveURL(/\/dashboard/);

    // Make sure the TOTP prompt is NOT visible
    const totpInput = page.getByLabel('2FA Code');
    await expect(totpInput).not.toBeVisible();

    await context.close();
  });
});
