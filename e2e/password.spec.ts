import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { completeStepUp } from './fixtures/stepup';
import { psql, refreshStepUpGrace } from './fixtures/helpers';

test.describe('Password Change', () => {
  test('mismatched passwords are rejected client-side (no step-up triggered)', async ({ page }) => {
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
  });

  test('password change goes through step-up and round-trips', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    const passwordHeading = page.getByText('Change Password');
    await passwordHeading.scrollIntoViewIfNeeded();

    // Change password — step-up modal will gate the request.
    await page.getByLabel('New Password').fill('newtest1234test');
    await page.getByLabel('Confirm Password').fill('newtest1234test');
    await page.getByRole('button', { name: 'Update Password' }).click();
    await completeStepUp(page, 'test1234test');
    await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 5000 });

    // Change it back within the step-up grace window (no second modal expected).
    // Refresh the grace server-side (deterministic) rather than relying on the
    // first change landing under STEP_UP_TTL — UI latency could otherwise push
    // the second change past the window and spuriously re-prompt.
    const userId = psql(`SELECT id FROM users WHERE email = 'test@test.com'`);
    refreshStepUpGrace(userId);
    await page.getByLabel('New Password').fill('test1234test');
    await page.getByLabel('Confirm Password').fill('test1234test');
    await page.getByRole('button', { name: 'Update Password' }).click();
    await expect(page.getByText(/password updated/i).first()).toBeVisible({ timeout: 5000 });
  });
});
