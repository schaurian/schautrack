import { test, expect } from '@playwright/test';
import { psql, generateTOTP, bcryptHash, expireStepUpGrace } from './fixtures/helpers';
import { completeStepUp } from './fixtures/stepup';

test.describe.configure({ mode: 'serial' });

const EMAIL = '2fa@test.com';
const PASSWORD = '2fa1234test';

let twoFaUserId = '';

let capturedSecret = '';
let capturedBackupCodes: string[] = [];

/**
 * Both steps of the login — credentials and 2FA code — POST to this one
 * endpoint, so both are awaited the same way.
 *
 * The 403 is skipped because it is never an answer: api/client.ts treats a 403
 * on a mutating request as a stale CSRF token, refetches /api/csrf and re-POSTs
 * once, so the 403 is the first half of a request that has not finished yet.
 * Resolving on it would hand the caller a reply the app has already discarded —
 * submit2faCode would assert `expect(403).toBe(200)` and fail a login that in
 * fact succeeded, and loginAs2faUser would return before the real round-trip,
 * making the next assertion pay for an argon2id verification out of its own
 * budget. Only 403 is filtered, and only because handler.Login cannot produce
 * one: its own rejections are 400, 401 and 429, and those must still resolve
 * here so a genuine failure surfaces as a status assertion instead of a wait.
 *
 * Hardening, not a fix for anything observed — no run has been traced to this
 * path.
 */
function loginPosted(page: import('@playwright/test').Page) {
  return page.waitForResponse(
    (res) =>
      res.url().includes('/api/auth/login') &&
      res.request().method() === 'POST' &&
      res.status() !== 403,
    { timeout: 30000 },
  );
}

/**
 * Submit the credentials form and wait for the server's answer before
 * returning.
 *
 * Callers used to click and immediately assert on the UI, which quietly made
 * every one of those assertions pay for the request as well: the 10s allowed
 * for "the 2FA prompt rendered" was really "bcrypt compared the password while
 * three other workers hammered the same container, *and* the prompt rendered".
 * That is what timed out under load. Awaiting the POST separates the two, so
 * the render assertion gets its own full budget without anything being
 * lengthened.
 */
async function loginAs2faUser(page: import('@playwright/test').Page) {
  await page.goto('/login');
  await page.waitForLoadState('domcontentloaded');
  await page.getByLabel('Email').fill(EMAIL);
  await page.getByLabel('Password').fill(PASSWORD);
  const posted = loginPosted(page);
  await page.getByRole('button', { name: 'Log In' }).click();
  await posted;
}

/**
 * Enter a TOTP or backup code and land on the dashboard.
 *
 * Checking the verify response before waiting for the URL turns the one
 * failure that actually matters here — the server rejecting the code — into
 * "expected 200, received 401" instead of a 15s wait for a navigation that was
 * never coming, which is how it used to present.
 */
async function submit2faCode(page: import('@playwright/test').Page, code: string) {
  const codeInput = page.getByLabel('2FA Code');
  await expect(codeInput).toBeVisible({ timeout: 10000 });
  await codeInput.fill(code);
  const posted = loginPosted(page);
  await page.getByRole('button', { name: /verify/i }).click();
  expect((await posted).status()).toBe(200);
  await page.waitForURL('/dashboard', { timeout: 15000 });
}

async function logout(page: import('@playwright/test').Page) {
  // Logout now exists exactly once, on /account. It used to be duplicated as a
  // sidebar button on desktop plus an lg:hidden row in Settings on mobile,
  // which is why this needed visibility-aware matching to stay unambiguous.
  await page.goto('/account');
  await page.getByRole('button', { name: 'Logout' }).click();
  // useLogout() navigates to /login. The old /\/login|\// matched any URL with
  // a slash in it, so this returned before the logout had happened at all.
  await page.waitForURL(/\/login/, { timeout: 10000 });
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

    await page.goto('/account');
    await page.waitForURL('/account');

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

    // Should see the TOTP prompt (not redirect to dashboard yet), then verify.
    await submit2faCode(page, generateTOTP(capturedSecret));
    await expect(page).toHaveURL(/\/dashboard/);

    await logout(page);
    await context.close();
  });

  test('3. Log in with backup code', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await loginAs2faUser(page);

    // The same input accepts both TOTP and backup codes.
    expect(capturedBackupCodes.length).toBeGreaterThan(0);
    await submit2faCode(page, capturedBackupCodes[0]);
    await expect(page).toHaveURL(/\/dashboard/);

    await logout(page);
    await context.close();
  });

  test('4. Regenerate backup codes', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    // Login with TOTP
    await loginAs2faUser(page);
    await submit2faCode(page, generateTOTP(capturedSecret));

    await page.goto('/account');
    await page.waitForURL('/account');

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
    await submit2faCode(page, generateTOTP(capturedSecret));

    await page.goto('/account');
    await page.waitForURL('/account');

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
