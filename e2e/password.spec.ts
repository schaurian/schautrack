import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Password Change', () => {
  test('password change validates inputs', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Find the Change Password section
    const passwordHeading = page.getByText('Change Password');
    await expect(passwordHeading).toBeVisible({ timeout: 5000 });

    // Fill in mismatched passwords
    await page.getByLabel('Current Password').fill('test1234test');
    await page.getByLabel('New Password').fill('newpassword123');
    await page.getByLabel('Confirm Password').fill('differentpassword');

    // Submit
    await page.getByRole('button', { name: 'Update Password' }).click();

    // Should show error about passwords not matching
    await expect(page.getByText(/not match|mismatch/i)).toBeVisible({ timeout: 5000 });
  });

  test.skip('password change with correct inputs', async ({ page }) => {
    // SKIP: This test changes the password and can corrupt the test user if it fails midway
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    const passwordHeading = page.getByText('Change Password');
    await expect(passwordHeading).toBeVisible({ timeout: 5000 });

    // Change password
    await page.getByLabel('Current Password').fill('test1234test');
    await page.getByLabel('New Password').fill('newtest1234test');
    await page.getByLabel('Confirm Password').fill('newtest1234test');
    await page.getByRole('button', { name: 'Update Password' }).click();

    // Should show success
    await expect(page.getByText('Password updated').first()).toBeVisible({ timeout: 5000 });

    // Change it back so other tests still work
    await page.getByLabel('Current Password').fill('newtest1234test');
    await page.getByLabel('New Password').fill('test1234test');
    await page.getByLabel('Confirm Password').fill('test1234test');
    await page.getByRole('button', { name: 'Update Password' }).click();
    await expect(page.getByText('Password updated').first()).toBeVisible({ timeout: 5000 });
  });
});
