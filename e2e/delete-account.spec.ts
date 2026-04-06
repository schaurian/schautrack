import { test, expect } from '@playwright/test';
import { psql, bcryptHash } from './fixtures/helpers';

const DELETE_EMAIL = 'delete-e2e@test.com';
const DELETE_PASSWORD = 'deletetest1234';

function ensureDeleteUser() {
  const hash = bcryptHash(DELETE_PASSWORD);
  const exists = psql(`SELECT id FROM users WHERE email = '${DELETE_EMAIL}'`);
  if (exists) {
    psql(`UPDATE users SET password_hash = '${hash}', email_verified = true, totp_enabled = false, totp_secret = NULL WHERE email = '${DELETE_EMAIL}'`);
    psql(`DELETE FROM totp_backup_codes WHERE user_id = ${exists}`);
  } else {
    psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${DELETE_EMAIL}', '${hash}', true)`);
  }
}

test.describe('Delete Account', () => {
  test.beforeAll(() => {
    ensureDeleteUser();
  });

  test('user can delete their own account', async ({ browser }) => {
    // Log in as the disposable user in a fresh context
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/login');
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(DELETE_EMAIL);
    await page.getByLabel('Password').fill(DELETE_PASSWORD);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL('/dashboard', { timeout: 15000 });

    // Navigate to the delete account page
    await page.goto('/delete');
    await page.waitForLoadState('domcontentloaded');

    // The delete page should show the confirmation form
    await expect(page.getByRole('heading', { name: 'Delete Account' })).toBeVisible({ timeout: 5000 });
    await expect(page.getByLabel('Password')).toBeVisible({ timeout: 5000 });

    // Fill in the password and submit
    await page.getByLabel('Password').fill(DELETE_PASSWORD);
    await page.getByRole('button', { name: 'Delete My Account' }).click();

    // Should show success and redirect to landing page (/)
    await expect(page.getByText(/Account deleted/i)).toBeVisible({ timeout: 5000 });
    await page.waitForURL('/', { timeout: 10000 });

    await context.close();

    // Verify the account is truly gone by trying to log in again in a new context
    const verifyContext = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const verifyPage = await verifyContext.newPage();

    await verifyPage.goto('/login');
    await verifyPage.waitForLoadState('domcontentloaded');
    await verifyPage.getByLabel('Email').fill(DELETE_EMAIL);
    await verifyPage.getByLabel('Password').fill(DELETE_PASSWORD);
    await verifyPage.getByRole('button', { name: 'Log In' }).click();

    // Should get an error — the account no longer exists
    await expect(verifyPage.getByText(/Invalid credentials/i)).toBeVisible({ timeout: 5000 });

    await verifyContext.close();
  });
});
