import { expect, type Page } from '@playwright/test';

/**
 * Complete the step-up modal that opens when a sensitive auth-method change
 * is triggered without a fresh elevated session.
 *
 * Use the `password` form. If the user has TOTP enabled, pass `totp` (raw
 * 6-digit code or backup code).
 */
export async function completeStepUp(page: Page, password: string, totp?: string) {
  const dialog = page.getByRole('dialog', { name: /confirm it's you/i });
  await expect(dialog).toBeVisible({ timeout: 5000 });

  // The modal renders its own Password input — scope to the dialog so we
  // don't collide with "New Password" / "Confirm Password" fields on the
  // settings forms behind it.
  await dialog.getByLabel('Password', { exact: true }).fill(password);
  if (totp) {
    await dialog.getByLabel('2FA Code').fill(totp);
  }
  await dialog.getByRole('button', { name: 'Continue' }).click();

  // Modal closes once step-up succeeds and the original request returns.
  await expect(dialog).not.toBeVisible({ timeout: 10000 });
}

/**
 * Cancel the step-up modal. Resolves the original request with a rejection,
 * leaving the user's form untouched.
 */
export async function cancelStepUp(page: Page) {
  const dialog = page.getByRole('dialog', { name: /confirm it's you/i });
  await expect(dialog).toBeVisible({ timeout: 5000 });
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).not.toBeVisible({ timeout: 5000 });
}
