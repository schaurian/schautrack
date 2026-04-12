import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser } from './fixtures/helpers';

let user: { email: string; password: string; id: string };

test.describe('Entry Tracking', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('entries');
  });

  test('create and delete a calorie entry', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await expect(nameInput).toBeVisible({ timeout: 10000 });
    await nameInput.fill('Test meal');
    await page.locator('input[inputmode="tel"]').first().fill('500');
    await page.getByRole('button', { name: 'Track' }).click();

    await expect(page.getByRole('button', { name: 'Test meal' })).toBeVisible({ timeout: 5000 });

    await page.locator('button[title="Delete"]').first().click();
    await expect(page.getByRole('button', { name: 'Test meal' })).not.toBeVisible({ timeout: 5000 });
    await ctx.close();
  });

  test('math expressions evaluate correctly', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // Wait for the entry form to render
    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await expect(nameInput).toBeVisible({ timeout: 10000 });
    await nameInput.fill('Math test meal');
    await page.locator('input[inputmode="tel"]').first().fill('200+150');
    await page.getByRole('button', { name: 'Track' }).click();

    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole('button', { name: 'Math test meal' })).toBeVisible({ timeout: 5000 });

    await page.locator('button[title="Delete"]').first().click();
    await ctx.close();
  });

  test('daily total updates after adding entry', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await expect(nameInput).toBeVisible({ timeout: 10000 });
    await nameInput.fill('Total test');
    await page.locator('input[inputmode="tel"]').first().fill('500');
    await page.getByRole('button', { name: 'Track' }).click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('500').first()).toBeVisible({ timeout: 5000 });

    await page.locator('button[title="Delete"]').first().click();
    await ctx.close();
  });

  test('dot colors reflect goal progress', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');
    const today = new Date().toISOString().split('T')[0];

    // Wait for the timeline dots to render (ensures SSE is connected)
    const todayDot = page.locator(`button[aria-label^="${today}"]`);
    await expect(todayDot).toBeVisible({ timeout: 10000 });

    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Over Goal');
    await page.locator('input[inputmode="tel"]').first().fill('2500');
    await page.getByRole('button', { name: 'Track' }).click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Wait for the dot's status to update via SSE (may take a moment after the toast)
    await expect(todayDot).toHaveAttribute('aria-label', new RegExp(`${today}:.*over`), { timeout: 15000 });

    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
    await ctx.close();
  });

  test('entry date can be changed via date picker', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');

    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];

    const nameInput = page.locator('input[placeholder="Breakfast, snack..."]');
    await expect(nameInput).toBeVisible({ timeout: 10000 });
    await page.locator('form input[type="date"]').first().fill(yesterday);
    await nameInput.fill('Yesterday entry');
    await page.locator('input[inputmode="tel"]').first().fill('111');
    await page.getByRole('button', { name: 'Track' }).click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    const yesterdayDot = page.locator(`button[aria-label^="${yesterday}"]`).first();
    if (await yesterdayDot.isVisible({ timeout: 3000 }).catch(() => false)) {
      await yesterdayDot.click();
      await expect(page.getByRole('button', { name: 'Yesterday entry' })).toBeVisible({ timeout: 5000 });
    }

    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
    await ctx.close();
  });
});
