import { test as base, expect, Page } from '@playwright/test';

/**
 * Log in as the test user. For tests that use storageState (most tests),
 * the session is already loaded — this just navigates to dashboard.
 * For auth tests that need fresh login, this does the full flow.
 */
export async function login(page: Page) {
  // If we have a valid session (from storageState), just navigate
  await page.goto('/dashboard');
  try {
    await page.waitForURL('/dashboard', { timeout: 5000 });
    return;
  } catch {
    // No session — do fresh login
  }

  await page.goto('/login');
  await page.waitForLoadState('domcontentloaded');
  await page.getByLabel('Email').fill('test@test.com');
  await page.getByLabel('Password').fill('test1234test');
  await page.getByRole('button', { name: 'Log In' }).click();
  await page.waitForURL('/dashboard', { timeout: 15000 });
}

export { base as test, expect };
