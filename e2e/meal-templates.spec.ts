import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser } from './fixtures/helpers';

let user: { email: string; password: string; id: string };

test.describe('Meal templates', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('meal-templates');
  });

  test.beforeEach(() => {
    psql(`DELETE FROM meal_templates WHERE user_id = ${user.id}`);
    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
  });

  test('create template, star it, apply from Dashboard, delete', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);

    // Create template via the Templates page
    await page.goto('/templates');
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByRole('heading', { name: 'Meal templates' })).toBeVisible({ timeout: 10000 });

    await page.getByRole('button', { name: 'New template' }).click();
    await page.locator('input#template-name').fill('Breakfast combo');
    await page.getByLabel('Show in Dashboard Quick-Add').check();

    // First item (pre-filled row)
    const inputs = page.locator('input[placeholder="Name (e.g. Oatmeal)"]');
    await inputs.nth(0).fill('Oatmeal');
    const kcalInputs = page.locator('input[placeholder="kcal"]');
    await kcalInputs.nth(0).fill('300');

    // Add a second item
    await page.getByRole('button', { name: '+ Add item' }).click();
    await inputs.nth(1).fill('Banana');
    await kcalInputs.nth(1).fill('110');

    await page.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByText('Template created')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('Breakfast combo')).toBeVisible({ timeout: 5000 });

    // Switch to Dashboard and confirm favorites chip
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');
    const chip = page.getByRole('button', { name: /Breakfast combo/ });
    await expect(chip).toBeVisible({ timeout: 10000 });

    // Apply via chip — expect 2 new entries
    await chip.click();
    await expect(page.getByText('Added 2 entries')).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole('button', { name: 'Oatmeal' })).toBeVisible({ timeout: 5000 });
    await expect(page.getByRole('button', { name: 'Banana' })).toBeVisible({ timeout: 5000 });

    // Unstar in the Templates page → chip disappears
    await page.goto('/templates');
    await page.waitForLoadState('domcontentloaded');
    await page.getByRole('button', { name: 'Remove from favorites' }).click();

    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByRole('button', { name: /Breakfast combo/ })).not.toBeVisible({ timeout: 5000 });

    // Delete template
    page.once('dialog', (dialog) => dialog.accept());
    await page.goto('/templates');
    await page.waitForLoadState('domcontentloaded');
    await page.getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByText('Template deleted')).toBeVisible({ timeout: 5000 });
    await expect(page.getByText('Breakfast combo')).not.toBeVisible({ timeout: 5000 });

    await ctx.close();
  });

  test('validation: template needs at least one item', async ({ browser }) => {
    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/templates');
    await page.waitForLoadState('domcontentloaded');

    await page.getByRole('button', { name: /New template|Create your first template/ }).click();
    await page.locator('input#template-name').fill('Empty');
    await page.getByRole('button', { name: 'Create' }).click();
    await expect(
      page.getByText(/at least one item|name, calories, or macros/i),
    ).toBeVisible({ timeout: 5000 });

    await ctx.close();
  });
});
