import { test, expect } from '@playwright/test';

test.describe('Registration', () => {
  test('registration page loads with form', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/register');

    // Email and password fields should be visible
    await expect(page.getByLabel('Email')).toBeVisible({ timeout: 5000 });
    await expect(page.getByLabel('Password')).toBeVisible();

    await context.close();
  });

  test('navigate between login and register', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/login');
    await page.getByText('Create account').click();
    await expect(page).toHaveURL(/\/register/);

    await page.getByText('Already have an account?').click();
    await expect(page).toHaveURL(/\/login/);

    await context.close();
  });

  test('confirm password mismatch shows red border', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/register');
    await page.getByLabel('Password').fill('test1234test');
    await page.getByLabel('Confirm Password').fill('different');
    // Blur the confirm field to trigger validation
    await page.getByLabel('Confirm Password').blur();

    // The Input component adds border-destructive when error prop is set
    const confirmInput = page.locator('input[type="password"]').last();
    await expect(confirmInput).toHaveClass(/border-destructive/);

    // Error message should also appear
    await expect(page.getByText('Passwords do not match.')).toBeVisible();

    await context.close();
  });

  test('confirm password match shows green border', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/register');
    await page.getByLabel('Password').fill('test1234test');
    await page.getByLabel('Confirm Password').fill('test1234test');
    // Blur to trigger touched state
    await page.getByLabel('Confirm Password').blur();

    // The Register component applies border-green-500 className when passwords match and field is touched
    const confirmInput = page.locator('input[type="password"]').last();
    await expect(confirmInput).toHaveClass(/border-green-500/);

    await context.close();
  });

  test('submit button disabled until all fields valid', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/register');

    // Button should be disabled with empty fields
    const submitButton = page.getByRole('button', { name: 'Continue' });
    await expect(submitButton).toBeDisabled();

    // Fill email only — still disabled
    await page.getByLabel('Email').fill('newuser@example.com');
    await expect(submitButton).toBeDisabled();

    // Fill password only — still disabled (no confirm)
    await page.getByLabel('Password').fill('test1234test');
    await expect(submitButton).toBeDisabled();

    // Fill confirm with mismatched value — still disabled
    await page.getByLabel('Confirm Password').fill('different');
    await expect(submitButton).toBeDisabled();

    // Fix confirm password to match — now enabled
    await page.getByLabel('Confirm Password').fill('test1234test');
    await expect(submitButton).toBeEnabled();

    await context.close();
  });
});
