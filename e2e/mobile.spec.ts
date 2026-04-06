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

  test('calorie input has inputmode="tel"', async ({ page }) => {
    await login(page);

    // The calorie input uses inputMode="tel" so mobile devices show a numeric keypad
    const calorieInput = page.locator('input[inputmode="tel"]');
    await expect(calorieInput).toBeVisible({ timeout: 10000 });
    await expect(calorieInput).toHaveAttribute('inputmode', 'tel');
  });

  test('active nav item is visually highlighted', async ({ page }) => {
    await login(page);

    // Open the mobile menu
    await page.getByRole('button', { name: 'Toggle menu' }).click();

    // Dashboard link should be active — it gets bg-[#0ea5e9]/[0.14] and border-l-[#0ea5e9] on mobile
    const dashboardLink = page.getByRole('link', { name: 'Dashboard' });
    await expect(dashboardLink).toBeVisible();
    // The active nav class includes border-l-[#0ea5e9] on mobile
    await expect(dashboardLink).toHaveClass(/border-\[#0ea5e9\]/);

    // Navigate to Settings and verify its link becomes active instead
    await page.getByRole('link', { name: 'Settings' }).click();
    await page.waitForURL('/settings');

    // Re-open menu
    await page.getByRole('button', { name: 'Toggle menu' }).click();

    const settingsLink = page.getByRole('link', { name: 'Settings' });
    await expect(settingsLink).toBeVisible();
    await expect(settingsLink).toHaveClass(/border-\[#0ea5e9\]/);

    // Dashboard should no longer have the active border
    const dashboardLinkInactive = page.getByRole('link', { name: 'Dashboard' });
    await expect(dashboardLinkInactive).not.toHaveClass(/border-\[#0ea5e9\]/);
  });

  test('dashboard has no horizontal scroll on mobile', async ({ page }) => {
    await login(page);
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // Wait for dashboard to render before measuring
    await expect(page.locator('input[placeholder="Breakfast, snack..."]')).toBeVisible({ timeout: 10000 });

    const hasHorizontalScroll = await page.evaluate(() => {
      return document.documentElement.scrollWidth > document.documentElement.clientWidth;
    });

    expect(hasHorizontalScroll).toBe(false);
  });

  test('entry form is functional on mobile viewport', async ({ page }) => {
    await login(page);
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    // The entry form inputs must be visible and interactive on a 390px wide viewport
    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await expect(nameInput).toBeVisible({ timeout: 10000 });

    const calorieInput = page.locator('input[inputmode="tel"]');
    await expect(calorieInput).toBeVisible({ timeout: 5000 });

    // Verify we can type into both fields
    await nameInput.fill('Mobile test meal');
    await expect(nameInput).toHaveValue('Mobile test meal');

    await calorieInput.fill('500');
    await expect(calorieInput).toHaveValue('500');

    // Clean up — clear the fields without submitting
    await nameInput.fill('');
    await calorieInput.fill('');
  });

  test('note editor is visible and accepts input on mobile', async ({ page }) => {
    await login(page);

    // Enable daily notes via the API (CSRF token required for POST)
    await page.evaluate(async () => {
      const csrfRes = await fetch('/api/csrf');
      const { token } = await csrfRes.json();
      await fetch('/api/notes/toggle-enabled', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify({ enabled: true }),
      });
    });

    // Reload so the dashboard picks up the enabled notes setting
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    const noteTextarea = page.locator('textarea[placeholder="Write a note for this day..."]');
    await expect(noteTextarea).toBeVisible({ timeout: 10000 });

    // Verify the textarea accepts text input
    await noteTextarea.fill('Mobile note test');
    await expect(noteTextarea).toHaveValue('Mobile note test');

    // Clean up — disable notes again so other tests are unaffected
    await page.evaluate(async () => {
      const csrfRes = await fetch('/api/csrf');
      const { token } = await csrfRes.json();
      await fetch('/api/notes/toggle-enabled', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
        body: JSON.stringify({ enabled: false }),
      });
    });
  });
});
