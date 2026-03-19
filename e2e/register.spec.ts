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
});
