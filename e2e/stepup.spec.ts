import { test, expect } from '@playwright/test';
import { createIsolatedUser } from './fixtures/helpers';
import { completeStepUp, cancelStepUp } from './fixtures/stepup';

// Each test uses a fresh login context so the storageState session age can't
// influence whether the step-up grace is fresh. Tests share one DB user and
// mutate the password, so they must run serially to avoid clobbering each
// other's logins.
test.describe.configure({ mode: 'serial' });

test.describe('Step-up auth', () => {
  let user: { email: string; password: string; id: string };

  test.beforeAll(() => {
    user = createIsolatedUser('stepup');
  });

  async function login(page: import('@playwright/test').Page) {
    await page.goto('/login');
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL('/dashboard', { timeout: 15000 });
  }

  test('fresh login grants the grace window — first sensitive action skips modal', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);

    // Immediately after login, step-up is fresh. Password change should go
    // through without prompting.
    await page.goto('/settings');
    await page.waitForURL('/settings');
    await page.getByText('Change Password').scrollIntoViewIfNeeded();

    const newPw = 'fresh-grace-pw-1';
    await page.getByLabel('New Password').fill(newPw);
    await page.getByLabel('Confirm Password').fill(newPw);
    await page.getByRole('button', { name: 'Update Password' }).click();

    await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole('dialog', { name: /confirm it's you/i })).not.toBeVisible();

    // Restore original password (still in grace).
    await page.getByLabel('New Password').fill(user.password);
    await page.getByLabel('Confirm Password').fill(user.password);
    await page.getByRole('button', { name: 'Update Password' }).click();
    await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 5000 });

    await ctx.close();
  });

  test('expired grace re-prompts; completing the modal retries the original request', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);

    await page.goto('/settings');
    await page.waitForURL('/settings');

    // STEP_UP_TTL=10s in compose.test.yml — wait long enough that the grace
    // expires before we trigger a sensitive action.
    await page.waitForTimeout(12000);

    await page.getByText('Change Password').scrollIntoViewIfNeeded();
    const newPw = 'after-expiry-pw-1';
    await page.getByLabel('New Password').fill(newPw);
    await page.getByLabel('Confirm Password').fill(newPw);
    await page.getByRole('button', { name: 'Update Password' }).click();

    // Step-up modal must appear, and on completion the original request runs.
    await completeStepUp(page, user.password);
    await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 5000 });

    // Restore password — within fresh grace from the step-up just completed.
    await page.getByLabel('New Password').fill(user.password);
    await page.getByLabel('Confirm Password').fill(user.password);
    await page.getByRole('button', { name: 'Update Password' }).click();
    await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 5000 });

    await ctx.close();
  });

  test('cancelling the modal rejects the original request', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);

    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Wait past grace so the modal triggers.
    await page.waitForTimeout(12000);

    await page.getByText('Change Password').scrollIntoViewIfNeeded();
    await page.getByLabel('New Password').fill('cancel-test-pw-1');
    await page.getByLabel('Confirm Password').fill('cancel-test-pw-1');
    await page.getByRole('button', { name: 'Update Password' }).click();

    await cancelStepUp(page);

    // Original request rejected — no success message, password unchanged.
    await expect(page.getByText(/password updated/i)).not.toBeVisible({ timeout: 1000 });
    // The form is still rendered with our entered values.
    await expect(page.getByLabel('New Password')).toHaveValue('cancel-test-pw-1');

    await ctx.close();
  });

  test('wrong password in step-up shows error, modal stays open', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);

    await page.goto('/settings');
    await page.waitForURL('/settings');
    await page.waitForTimeout(12000);

    await page.getByText('Change Password').scrollIntoViewIfNeeded();
    await page.getByLabel('New Password').fill('wrong-pw-test');
    await page.getByLabel('Confirm Password').fill('wrong-pw-test');
    await page.getByRole('button', { name: 'Update Password' }).click();

    const dialog = page.getByRole('dialog', { name: /confirm it's you/i });
    await expect(dialog).toBeVisible({ timeout: 5000 });
    await dialog.getByLabel('Password', { exact: true }).fill('definitely-wrong-password');
    await dialog.getByRole('button', { name: 'Continue' }).click();

    // Modal stays open with an error.
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText(/invalid credentials/i)).toBeVisible({ timeout: 5000 });

    // Recover with the correct password.
    await dialog.getByLabel('Password', { exact: true }).fill(user.password);
    await dialog.getByRole('button', { name: 'Continue' }).click();
    await expect(dialog).not.toBeVisible({ timeout: 10000 });
    await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 5000 });

    // Restore original password — within fresh grace, no second modal.
    await page.getByLabel('New Password').fill(user.password);
    await page.getByLabel('Confirm Password').fill(user.password);
    await page.getByRole('button', { name: 'Update Password' }).click();
    await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 5000 });

    await ctx.close();
  });
});
