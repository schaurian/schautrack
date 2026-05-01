import { test, expect } from '@playwright/test';
import { createIsolatedUser, psql } from './fixtures/helpers';
import { completeStepUp } from './fixtures/stepup';
import { attachVirtualAuthenticator } from './fixtures/webauthn';

// Requires PASSKEYS_RP_ID + PASSKEYS_RP_ORIGINS on the test server (set in
// compose.test.yml). The virtual WebAuthn authenticator attached per test
// handles credentials.create / credentials.get without real biometrics.

test.describe('Passkeys', () => {
  let user: { email: string; password: string; id: string };

  test.beforeAll(() => {
    user = createIsolatedUser('passkey');
  });

  test.afterEach(async () => {
    psql(`DELETE FROM user_passkeys WHERE user_id = ${user.id}`);
  });

  async function login(page: import('@playwright/test').Page) {
    await page.goto('/login');
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL('/dashboard', { timeout: 15000 });
  }

  test('register a passkey via virtual authenticator (with step-up after grace)', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    const { teardown } = await attachVirtualAuthenticator(ctx, page);

    try {
      await login(page);
      await page.goto('/settings');

      // Wait past grace so step-up gates the registration call.
      await page.waitForTimeout(12000);

      const passkeyHeading = page.getByRole('heading', { name: /passkeys/i });
      await passkeyHeading.scrollIntoViewIfNeeded();

      await page.getByPlaceholder(/passkey name/i).fill('Test Authenticator');
      await page.getByRole('button', { name: /add passkey/i }).click();

      // Step-up gates the begin call.
      await completeStepUp(page, user.password);

      // The virtual authenticator handles the WebAuthn ceremony silently;
      // success toast confirms the round trip.
      await expect(page.getByText(/passkey registered/i)).toBeVisible({ timeout: 10000 });

      // The passkey appears in the list.
      await expect(page.getByText('Test Authenticator')).toBeVisible({ timeout: 5000 });

      // DB has it stored with backup flags persisted (regression check —
      // missing flags caused login to fail with "Backup Eligible flag
      // inconsistency" before BE/BS columns were added).
      const count = psql(`SELECT count(*) FROM user_passkeys WHERE user_id = ${user.id}`);
      expect(count).toBe('1');
    } finally {
      await teardown();
      await ctx.close();
    }
  });

  test('discoverable passkey login bypasses password', async ({ browser }) => {
    // Pre-register a passkey via the UI in one context, then sign out and log
    // back in with the passkey.
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    const { teardown } = await attachVirtualAuthenticator(ctx, page);

    try {
      await login(page);
      await page.goto('/settings');
      await page.waitForTimeout(12000);

      await page.getByRole('heading', { name: /passkeys/i }).scrollIntoViewIfNeeded();
      await page.getByPlaceholder(/passkey name/i).fill('Login Test');
      await page.getByRole('button', { name: /add passkey/i }).click();
      await completeStepUp(page, user.password);
      await expect(page.getByText(/passkey registered/i)).toBeVisible({ timeout: 10000 });

      // Log out, then sign in with the passkey (no password).
      await page.getByText('Logout').click();
      await page.waitForURL(/\/login|\/$/, { timeout: 10000 });

      await page.goto('/login');
      await page.getByRole('button', { name: /sign in with passkey/i }).click();

      await page.waitForURL('/dashboard', { timeout: 15000 });
      await expect(page).toHaveURL(/\/dashboard/);
    } finally {
      await teardown();
      await ctx.close();
    }
  });

  test('delete passkey requires step-up', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    const { teardown } = await attachVirtualAuthenticator(ctx, page);

    try {
      await login(page);
      await page.goto('/settings');
      await page.waitForTimeout(12000);

      // Register one passkey (step-up).
      await page.getByRole('heading', { name: /passkeys/i }).scrollIntoViewIfNeeded();
      await page.getByPlaceholder(/passkey name/i).fill('To Be Deleted');
      await page.getByRole('button', { name: /add passkey/i }).click();
      await completeStepUp(page, user.password);
      await expect(page.getByText('To Be Deleted')).toBeVisible({ timeout: 10000 });

      // Wait past grace to force the delete to require fresh step-up.
      await page.waitForTimeout(12000);

      // Click Remove on the passkey row.
      const row = page.locator('div').filter({ hasText: /^To Be Deleted/ });
      await row.getByRole('button', { name: /remove/i }).click();

      // Step-up modal opens for the delete; complete it.
      await completeStepUp(page, user.password);

      await expect(page.getByText(/passkey removed/i)).toBeVisible({ timeout: 5000 });
      await expect(page.getByText('To Be Deleted')).not.toBeVisible();
    } finally {
      await teardown();
      await ctx.close();
    }
  });
});
