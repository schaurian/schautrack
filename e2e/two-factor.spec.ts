import { test, expect } from '@playwright/test';
import { psql, generateTOTP, bcryptHash } from './fixtures/helpers';

test.describe.configure({ mode: 'serial' });

const EMAIL = '2fa@test.com';
const PASSWORD = '2fa1234test';

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
  await page.getByText('Logout').click();
  await page.waitForURL(/\/login|\//, { timeout: 10000 });
}

test.describe('Two-Factor Authentication', () => {
  test.beforeAll(() => {
    // Reset 2FA state for the test user before the suite runs
    const hash = bcryptHash(PASSWORD);
    const id = psql(`SELECT id FROM users WHERE email = '${EMAIL}'`);
    if (id) {
      psql(`UPDATE users SET password_hash = '${hash}', totp_enabled = false, totp_secret = NULL WHERE id = ${id}`);
      psql(`DELETE FROM totp_backup_codes WHERE user_id = ${id}`);
    }
  });

  test.skip('1. Enable 2FA', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await loginAs2faUser(page);
    await page.waitForURL('/dashboard', { timeout: 15000 });

    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Find and click the Setup 2FA button
    const setup2faBtn = page.getByRole('button', { name: /setup 2fa/i });
    await expect(setup2faBtn).toBeVisible({ timeout: 10000 });
    await setup2faBtn.click();

    // Intercept the setup response to capture the secret
    const setupResponse = await page.waitForResponse(
      (resp) => resp.url().includes('/api/2fa/setup') && resp.status() === 200
    );
    const setupData = await setupResponse.json();
    expect(setupData.ok).toBe(true);
    expect(setupData.secret).toBeTruthy();
    capturedSecret = setupData.secret;

    // Generate a TOTP code and fill in the verification input
    const totpCode = generateTOTP(capturedSecret);
    const verificationInput = page.getByPlaceholder(/6-digit|verification code/i).or(
      page.getByLabel(/verification code/i)
    );
    await expect(verificationInput).toBeVisible({ timeout: 10000 });
    await verificationInput.fill(totpCode);

    // Click Activate button and capture the enable response
    const activateBtn = page.getByRole('button', { name: /activate/i });
    await expect(activateBtn).toBeVisible({ timeout: 5000 });

    const enableResponsePromise = page.waitForResponse(
      (resp) => resp.url().includes('/api/2fa/enable') && resp.status() === 200
    );
    await activateBtn.click();
    const enableResponse = await enableResponsePromise;
    const enableData = await enableResponse.json();
    expect(enableData.ok).toBe(true);
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
    const totpInput = page.getByPlaceholder(/enter 6-digit code/i);
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

    // Should see TOTP prompt
    const totpInput = page.getByPlaceholder(/enter 6-digit code/i);
    await expect(totpInput).toBeVisible({ timeout: 10000 });

    // Toggle to backup code input
    const useBackupLink = page.getByText(/backup code|use backup/i);
    if (await useBackupLink.isVisible({ timeout: 2000 }).catch(() => false)) {
      await useBackupLink.click();
    }

    // Fill in a backup code
    const backupInput = page.getByPlaceholder(/enter 8-digit backup code/i).or(
      page.getByPlaceholder(/backup code/i)
    );
    const backupCodeToUse = capturedBackupCodes[0];

    if (await backupInput.isVisible({ timeout: 3000 }).catch(() => false)) {
      await backupInput.fill(backupCodeToUse);
    } else {
      // Some implementations accept it in the same input
      await totpInput.fill(backupCodeToUse);
    }

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
    const totpInput = page.getByPlaceholder(/enter 6-digit code/i);
    await expect(totpInput).toBeVisible({ timeout: 10000 });
    await totpInput.fill(generateTOTP(capturedSecret));
    await page.getByRole('button', { name: /verify/i }).click();
    await page.waitForURL('/dashboard', { timeout: 15000 });

    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Click regenerate backup codes button
    const regenBtn = page.getByRole('button', { name: /regenerate backup codes/i });
    await expect(regenBtn).toBeVisible({ timeout: 10000 });
    await regenBtn.click();

    // A TOTP input should appear to confirm the action
    const confirmInput = page.getByPlaceholder(/6-digit/i).or(
      page.getByLabel(/verification code|totp|authenticator/i)
    );
    await expect(confirmInput).toBeVisible({ timeout: 5000 });
    await confirmInput.fill(generateTOTP(capturedSecret));

    // Intercept the regenerate response
    const regenResponsePromise = page.waitForResponse(
      (resp) => resp.url().includes('/api/2fa/backup-codes') && resp.status() === 200
    );
    await page.getByRole('button', { name: /regenerate/i }).click();
    const regenResponse = await regenResponsePromise;
    const regenData = await regenResponse.json();
    expect(regenData.ok).toBe(true);
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
    const totpInput = page.getByPlaceholder(/enter 6-digit code/i);
    await expect(totpInput).toBeVisible({ timeout: 10000 });
    await totpInput.fill(generateTOTP(capturedSecret));
    await page.getByRole('button', { name: /verify/i }).click();
    await page.waitForURL('/dashboard', { timeout: 15000 });

    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Find the disable 2FA section and fill in TOTP
    const disableInput = page.getByPlaceholder(/6-digit/i).last().or(
      page.locator('input[type="text"]').filter({ hasText: '' }).last()
    );

    // Look for the disable form's input specifically
    const disableSection = page.locator('text=Disable 2FA').locator('..');
    const disableFormInput = disableSection.locator('input').or(
      page.getByRole('textbox').filter({ hasText: '' })
    );

    // Try finding by placeholder or proximity to "Disable 2FA" button
    const disableBtn = page.getByRole('button', { name: /disable 2fa/i });
    await expect(disableBtn).toBeVisible({ timeout: 10000 });

    // Scroll to disable section and fill the code input near it
    await disableBtn.scrollIntoViewIfNeeded();

    // Find the input in the disable 2FA card
    const inputs = page.locator('input[type="text"], input[type="number"], input[inputmode]');
    const inputCount = await inputs.count();
    // Fill the last visible input (likely the disable form's TOTP field)
    let filledDisableInput = false;
    for (let i = inputCount - 1; i >= 0; i--) {
      const input = inputs.nth(i);
      if (await input.isVisible()) {
        await input.fill(generateTOTP(capturedSecret));
        filledDisableInput = true;
        break;
      }
    }
    expect(filledDisableInput).toBe(true);

    await disableBtn.click();

    await expect(page.getByText(/2fa disabled/i)).toBeVisible({ timeout: 10000 });

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
    const totpInput = page.getByPlaceholder(/enter 6-digit code/i);
    await expect(totpInput).not.toBeVisible();

    await context.close();
  });
});
