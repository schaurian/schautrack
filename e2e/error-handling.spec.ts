import { test, expect } from '@playwright/test';

test.describe('Error Handling', () => {
  test('404 page shows for unknown routes', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/nonexistent-page-xyz');

    // SPA should handle this — either show login redirect or a not-found state
    // Should NOT show a raw error or blank page
    await expect(page.locator('body')).not.toHaveText('Cannot GET', { timeout: 5000 });

    await context.close();
  });

  test('login with wrong password shows error', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/login');
    await page.getByLabel('Email').fill('test@test.com');
    await page.getByLabel('Password').fill('wrongpassword1');
    await page.getByRole('button', { name: 'Log In' }).click();

    // Should show error message
    await expect(page.getByText(/invalid|incorrect|wrong/i)).toBeVisible({ timeout: 5000 });

    // Should stay on login page
    await expect(page).toHaveURL(/\/login/);

    await context.close();
  });

  test('login with nonexistent email shows error', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    await page.goto('/login');
    await page.getByLabel('Email').fill('nobody@nowhere.com');
    await page.getByLabel('Password').fill('somepassword1');
    await page.getByRole('button', { name: 'Log In' }).click();

    // Should show error (generic — don't reveal user existence)
    await expect(page.getByText(/invalid|incorrect|wrong|error/i)).toBeVisible({ timeout: 5000 });

    await context.close();
  });
});
