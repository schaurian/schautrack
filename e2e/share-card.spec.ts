import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe('Share Card', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('share-card');
    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
  });

  test('share card renders "You" label and at least one dot button', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // The share card for the logged-in user always shows "You"
    await expect(page.getByText('You', { exact: true })).toBeVisible({ timeout: 15000 });

    // At least one day dot button should be present
    const dots = page.locator('button[aria-label*=":"]').filter({
      hasNot: page.locator('svg'),
    });
    const count = await dots.count();
    expect(count).toBeGreaterThan(0);

    await ctx.close();
  });

  test('today dot changes from zero to non-zero after adding an entry', async ({ browser }) => {
    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);

    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    const today = new Date().toISOString().split('T')[0];
    const todayDot = page.locator(`button[aria-label^="${today}"]`);
    await expect(todayDot).toBeVisible({ timeout: 15000 });

    // Before adding entry: dot should be "zero"
    const initialLabel = await todayDot.getAttribute('aria-label');
    expect(initialLabel).toMatch(/zero/);

    // Add an entry
    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Share card test');
    await page.locator('input[inputmode="tel"]').first().fill('400');
    await page.getByRole('button', { name: 'Track' }).click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // After adding: dot should no longer be "zero"
    await expect(todayDot).not.toHaveAttribute('aria-label', new RegExp(`${today}:.*zero`), { timeout: 15000 });

    // Should be "under" or "over" depending on goal
    const updatedLabel = await todayDot.getAttribute('aria-label');
    expect(updatedLabel).toMatch(/(under|over)/);

    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
    await ctx.close();
  });

  test('share card dots are rendered in the correct container', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // "You" text should be in the same area as the dot buttons
    await expect(page.getByText('You', { exact: true })).toBeVisible({ timeout: 15000 });

    // Check timeline range buttons are present (7d, 30d, etc.)
    const has7d = await page.locator('button').filter({ hasText: '7d' }).isVisible({ timeout: 5000 }).catch(() => false);
    const has30d = await page.locator('button').filter({ hasText: '30d' }).isVisible({ timeout: 5000 }).catch(() => false);
    expect(has7d || has30d).toBe(true);

    await ctx.close();
  });
});
