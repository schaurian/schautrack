import { test, expect, Browser } from '@playwright/test';
import { clearMailpit, extractCodeFromEmail } from './fixtures/helpers';

const PASSWORD = 'verify1234test';

/**
 * Register a new user and land on /verify-email.
 * Returns the page (still inside the provided context).
 */
async function registerAndReachVerify(browser: Browser, email: string) {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const page = await context.newPage();

  await page.goto('/register');
  await page.waitForLoadState('domcontentloaded');

  // Step 1 — credentials
  await page.getByLabel('Email').fill(email);
  await page.locator('#password').fill(PASSWORD);
  await page.locator('#confirm-password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Continue' }).click();

  // Step 2 — captcha (CAPTCHA_BYPASS=true, any non-empty value passes)
  await expect(page.getByLabel('Captcha')).toBeVisible({ timeout: 5000 });
  await page.getByLabel('Captcha').fill('bypass');
  await page.getByRole('button', { name: 'Create Account' }).click();

  await page.waitForURL(/\/verify-email/, { timeout: 10000 });

  return { page, context };
}

test.describe('Email Verification', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeEach(async () => {
    await clearMailpit();
  });

  test('registration redirects to /verify-email', async ({ browser }) => {
    const email = `verify-redirect-${Date.now()}@test.com`;
    const { page, context } = await registerAndReachVerify(browser, email);

    await expect(page).toHaveURL(/\/verify-email/);
    await expect(page.getByLabel('Verification Code')).toBeVisible();

    await context.close();
  });

  test('correct verification code redirects to dashboard', async ({ browser }) => {
    const email = `verify-correct-${Date.now()}@test.com`;
    const { page, context } = await registerAndReachVerify(browser, email);

    const code = await extractCodeFromEmail(email, 30);
    await page.getByLabel('Verification Code').fill(code);
    await page.getByRole('button', { name: 'Verify' }).click();

    await page.waitForURL(/\/dashboard/, { timeout: 10000 });
    await expect(page).toHaveURL(/\/dashboard/);

    await context.close();
  });

  test('wrong verification code shows error and stays on page', async ({ browser }) => {
    const email = `verify-wrong-${Date.now()}@test.com`;
    const { page, context } = await registerAndReachVerify(browser, email);

    await page.getByLabel('Verification Code').fill('000000');
    await page.getByRole('button', { name: 'Verify' }).click();

    await expect(page.getByRole('alert')).toBeVisible({ timeout: 5000 });
    await expect(page).toHaveURL(/\/verify-email/);

    await context.close();
  });

  test('resend code button sends a new email and the new code verifies', async ({ browser }) => {
    const email = `verify-resend-${Date.now()}@test.com`;
    const { page, context } = await registerAndReachVerify(browser, email);

    // Clear mailpit so only the resent email is present
    await clearMailpit();

    await page.getByRole('button', { name: 'Resend Code' }).click();

    await expect(page.getByText(/new code sent/i)).toBeVisible({ timeout: 5000 });

    const newCode = await extractCodeFromEmail(email, 30);
    expect(newCode).toMatch(/^\d{6}$/);

    await page.getByLabel('Verification Code').fill(newCode);
    await page.getByRole('button', { name: 'Verify' }).click();

    await page.waitForURL(/\/dashboard/, { timeout: 10000 });
    await expect(page).toHaveURL(/\/dashboard/);

    await context.close();
  });
});
