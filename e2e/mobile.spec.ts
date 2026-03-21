import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.use({ viewport: { width: 390, height: 844 } });

test.describe('Mobile Viewport', () => {
  test('dashboard renders on mobile', async ({ page }) => {
    await login(page);

    // Dashboard should load without errors
    await expect(page.getByText('Something went wrong')).not.toBeVisible({ timeout: 3000 });

    // Key elements should be visible
    await expect(page.locator('input[placeholder="Breakfast, snack..."]')).toBeVisible();
  });

  test('settings page renders on mobile', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');
    await expect(page.getByText('Something went wrong')).not.toBeVisible({ timeout: 3000 });
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 15000 });
  });

  test('login page renders on mobile', async ({ browser }) => {
    const context = await browser.newContext({
      viewport: { width: 390, height: 844 },
      storageState: { cookies: [], origins: [] },
    });
    const page = await context.newPage();

    await page.goto('/login');
    await expect(page.getByLabel('Email')).toBeVisible();
    await expect(page.getByLabel('Password')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Log In' })).toBeVisible();

    await context.close();
  });
});
