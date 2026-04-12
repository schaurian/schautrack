import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Password Change', () => {
  test('password change validates mismatched inputs', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    const passwordHeading = page.getByText('Change Password');
    await passwordHeading.scrollIntoViewIfNeeded();
    await expect(passwordHeading).toBeVisible({ timeout: 5000 });

    await page.getByLabel('Current Password').fill('test1234test');
    await page.getByLabel('New Password').fill('newpassword123');
    await page.getByLabel('Confirm Password').fill('differentpassword');

    await page.getByRole('button', { name: 'Update Password' }).click();

    await expect(page.getByText(/not match|mismatch/i)).toBeVisible({ timeout: 5000 });
  });

  test('password change with correct inputs', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    const passwordHeading = page.getByText('Change Password');
    await passwordHeading.scrollIntoViewIfNeeded();

    // Change password
    await page.getByLabel('Current Password').fill('test1234test');
    await page.getByLabel('New Password').fill('newtest1234test');
    await page.getByLabel('Confirm Password').fill('newtest1234test');
    await page.getByRole('button', { name: 'Update Password' }).click();
    await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 5000 });

    // Change it back
    await page.getByLabel('Current Password').fill('newtest1234test');
    await page.getByLabel('New Password').fill('test1234test');
    await page.getByLabel('Confirm Password').fill('test1234test');
    await page.getByRole('button', { name: 'Update Password' }).click();
    await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 5000 });
  });
});
