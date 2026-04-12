import { test, expect } from '@playwright/test';
import { psql, bcryptHash, loginUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
const BCRYPT_EMAIL = 'e2e-bcrypt-migration@test.local';
const BCRYPT_PASSWORD = 'bcrypttest1234';

test.describe.serial('Bcrypt Migration', () => {
  test.beforeAll(() => {
    const hash = bcryptHash(BCRYPT_PASSWORD);
    psql(
      `INSERT INTO users (email, password_hash, email_verified)
       VALUES ('${BCRYPT_EMAIL}', '${hash}', true)
       ON CONFLICT (email) DO UPDATE SET password_hash = '${hash}', email_verified = true,
         totp_enabled = false, totp_secret = NULL`
    );
    const uid = psql(`SELECT id FROM users WHERE email = '${BCRYPT_EMAIL}'`);
    if (uid) {
      psql(`DELETE FROM calorie_entries WHERE user_id = ${uid}`);
    }
  });

  test.afterAll(() => {
    psql(`DELETE FROM users WHERE email = '${BCRYPT_EMAIL}'`);
  });

  test('bcrypt password hash allows login via UI', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    try {
      await page.goto(`${baseURL}/login`);
      await page.waitForLoadState('domcontentloaded');
      await page.getByLabel('Email').fill(BCRYPT_EMAIL);
      await page.getByLabel('Password').fill(BCRYPT_PASSWORD);
      await page.getByRole('button', { name: 'Log In' }).click();

      await page.waitForURL(/\/dashboard/, { timeout: 15000 });
      await expect(page).toHaveURL(/\/dashboard/);
    } finally {
      await context.close();
    }
  });

  test('after password change via settings, hash is upgraded to argon2id', async ({ browser }) => {
    // Ensure user has bcrypt hash before we start
    const hash = bcryptHash(BCRYPT_PASSWORD);
    psql(`UPDATE users SET password_hash = '${hash}' WHERE email = '${BCRYPT_EMAIL}'`);

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();
    const newPassword = 'argon2newpass1234';

    try {
      // Login with bcrypt password
      await page.goto(`${baseURL}/login`);
      await page.waitForLoadState('domcontentloaded');
      await page.getByLabel('Email').fill(BCRYPT_EMAIL);
      await page.getByLabel('Password').fill(BCRYPT_PASSWORD);
      await page.getByRole('button', { name: 'Log In' }).click();
      await page.waitForURL(/\/dashboard/, { timeout: 15000 });

      // Go to settings and change password
      await page.goto(`${baseURL}/settings`);
      await page.waitForURL(/\/settings/);

      const passwordHeading = page.getByText('Change Password');
      await passwordHeading.scrollIntoViewIfNeeded();
      await expect(passwordHeading).toBeVisible({ timeout: 10000 });

      await page.getByLabel('Current Password').fill(BCRYPT_PASSWORD);
      await page.getByLabel('New Password').fill(newPassword);
      await page.getByLabel('Confirm Password').fill(newPassword);
      await page.getByRole('button', { name: 'Update Password' }).click();

      await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 10000 });
    } finally {
      await context.close();
    }

    // Check the DB: hash should now be argon2id
    const newHash = psql(`SELECT password_hash FROM users WHERE email = '${BCRYPT_EMAIL}'`);
    expect(newHash).toBeTruthy();
    expect(newHash).toMatch(/^\$argon2id\$/);
    expect(newHash).not.toMatch(/^\$2[aby]\$/);
  });
});
