import { test, expect } from '@playwright/test';
import { createIsolatedUser, expireStepUpGrace, refreshStepUpGrace } from './fixtures/helpers';
import { completeStepUp } from './fixtures/stepup';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

// This spec mutates its user's password. It must run against an isolated user
// (not the shared test@test.com session) so it can't corrupt the fixed password
// that the auth/2fa/stepup projects log in with concurrently. Both tests share
// the isolated user and run serially so they can't clobber each other's logins.
test.describe('Password Change', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('password');
  });

  async function login(page: import('@playwright/test').Page) {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
  }

  test('mismatched passwords are rejected client-side (no step-up triggered)', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    const passwordHeading = page.getByText('Change Password');
    await passwordHeading.scrollIntoViewIfNeeded();
    await expect(passwordHeading).toBeVisible({ timeout: 5000 });

    await page.getByLabel('New Password').fill('newpassword123');
    await page.getByLabel('Confirm Password').fill('differentpassword');

    await page.getByRole('button', { name: 'Update Password' }).click();

    await expect(page.getByText(/not match|mismatch/i)).toBeVisible({ timeout: 5000 });
    // Step-up modal should not have appeared — we caught the mismatch locally.
    await expect(page.getByRole('dialog', { name: /confirm it's you/i })).not.toBeVisible();

    await ctx.close();
  });

  test('password change goes through step-up and round-trips', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // A fresh login grants the step-up grace window (login doubles as step-up).
    // Expire it server-side (deterministic) instead of sleeping out STEP_UP_TTL,
    // so the password change below actually triggers the step-up modal.
    expireStepUpGrace(user.id);

    const passwordHeading = page.getByText('Change Password');
    await passwordHeading.scrollIntoViewIfNeeded();

    // Change password — step-up modal will gate the request.
    await page.getByLabel('New Password').fill('newtest1234test');
    await page.getByLabel('Confirm Password').fill('newtest1234test');
    await page.getByRole('button', { name: 'Update Password' }).click();
    await completeStepUp(page, user.password);
    await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 5000 });

    // Change it back within the step-up grace window (no second modal expected).
    // Refresh the grace server-side (deterministic) so UI latency can't push the
    // second change past STEP_UP_TTL and spuriously re-prompt.
    refreshStepUpGrace(user.id);
    await page.getByLabel('New Password').fill(user.password);
    await page.getByLabel('Confirm Password').fill(user.password);
    await page.getByRole('button', { name: 'Update Password' }).click();
    await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 5000 });

    await ctx.close();
  });
});
