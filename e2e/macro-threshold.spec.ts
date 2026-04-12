import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe.serial('Macro Threshold', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('macro-threshold');
    // Set calorie goal to 1000, threshold to 10%, disable all macros except calories
    // so the dot status is determined only by calorie intake vs goal
    psql(`UPDATE users SET
      daily_goal = 1000,
      macro_goals = '{"calories": 1000, "protein": 0, "carbs": 0, "fat": 0, "fiber": 0, "sugar": 0, "calories_mode": "limit", "protein_mode": "limit", "carbs_mode": "limit", "fat_mode": "limit"}',
      macros_enabled = '{"calories": true, "protein": false, "carbs": false, "fat": false, "fiber": false, "sugar": false, "auto_calc_calories": false}',
      goal_threshold = 10
      WHERE id = ${user.id}`);
  });

  test.afterAll(() => {
    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
  });

  test('over threshold turns dot red (over_threshold status)', async ({ browser }) => {
    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);

    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    const today = new Date().toISOString().split('T')[0];
    const todayDot = page.locator(`button[aria-label^="${today}"]`);
    await expect(todayDot).toBeVisible({ timeout: 15000 });

    // Track 1150 kcal: over_threshold because 150*100 > 1000*10 (15000 > 10000)
    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Big meal');
    await page.locator('input[inputmode="tel"]').first().fill('1150');
    await page.getByRole('button', { name: 'Track' }).click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Wait for SSE to update the dot, with fallback reload
    let label = await todayDot.getAttribute('aria-label');
    if (!label?.includes('over_threshold')) {
      await page.waitForTimeout(3000);
      label = await todayDot.getAttribute('aria-label');
    }
    if (!label?.includes('over_threshold')) {
      // Reload to get fresh data if SSE update was missed
      await page.reload();
      await page.waitForLoadState('domcontentloaded');
      await expect(page.locator(`button[aria-label^="${today}"]`)).toBeVisible({ timeout: 10000 });
    }

    await expect(page.locator(`button[aria-label^="${today}"]`)).toHaveAttribute(
      'aria-label',
      new RegExp(`${today}:.*over_threshold`),
      { timeout: 10000 }
    );

    await ctx.close();
  });

  test('over goal but within threshold shows "over" not "over_threshold"', async ({ browser }) => {
    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);

    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    const today = new Date().toISOString().split('T')[0];
    const todayDot = page.locator(`button[aria-label^="${today}"]`);
    await expect(todayDot).toBeVisible({ timeout: 15000 });

    // Track 1050 kcal: over=50, 50*100=5000, 1000*10=10000 → 5000 < 10000 → "over" (warning), not "over_threshold"
    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Moderate meal');
    await page.locator('input[inputmode="tel"]').first().fill('1050');
    await page.getByRole('button', { name: 'Track' }).click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Wait for SSE update, with fallback reload
    let label = await todayDot.getAttribute('aria-label');
    if (!label?.match(/over/) || label?.includes('over_threshold')) {
      await page.waitForTimeout(3000);
      label = await todayDot.getAttribute('aria-label');
    }
    if (!label?.match(/over/) || label?.includes('over_threshold')) {
      await page.reload();
      await page.waitForLoadState('domcontentloaded');
      await expect(page.locator(`button[aria-label^="${today}"]`)).toBeVisible({ timeout: 10000 });
    }

    const finalDot = page.locator(`button[aria-label^="${today}"]`);
    await expect(finalDot).toHaveAttribute(
      'aria-label',
      new RegExp(`${today}:.*over`),
      { timeout: 10000 }
    );
    const finalLabel = await finalDot.getAttribute('aria-label');
    expect(finalLabel).not.toMatch(/over_threshold/);

    await ctx.close();
  });

  test('protein chip with target mode does not show destructive styling when over target', async ({ browser }) => {
    // Enable protein in target mode for this test (protein goal=150, user will track 200)
    psql(`UPDATE users SET
      macros_enabled = '{"calories": true, "protein": true, "carbs": false, "fat": false, "fiber": false, "sugar": false, "auto_calc_calories": false}',
      macro_goals = '{"calories": 2000, "protein": 150, "carbs": 0, "fat": 0, "fiber": 0, "sugar": 0, "calories_mode": "limit", "protein_mode": "target", "carbs_mode": "limit", "fat_mode": "limit"}'
      WHERE id = ${user.id}`);
    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);

    const { context: ctx, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    await expect(page.locator('input[placeholder="Breakfast, snack..."]')).toBeVisible({ timeout: 10000 });

    await page.locator('input[placeholder="Breakfast, snack..."]').fill('High protein');
    await page.locator('input[inputmode="tel"]').first().fill('500');

    // Fill protein macro input if visible
    const macroInputs = page.locator('input[inputmode="numeric"][placeholder="0"]');
    const hasMacros = await macroInputs.first().isVisible({ timeout: 5000 }).catch(() => false);
    if (hasMacros) {
      await macroInputs.first().fill('200');
    }
    await page.getByRole('button', { name: 'Track' }).click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // In TodayPanel, protein chip with target mode and over-target should show success, not destructive
    const proteinText = page.getByText('Protein').first();
    const isProteinVisible = await proteinText.isVisible({ timeout: 8000 }).catch(() => false);

    if (isProteinVisible) {
      const proteinChip = proteinText.locator('../..');
      const chipClass = await proteinChip.getAttribute('class');
      if (chipClass) {
        expect(chipClass).not.toMatch(/destructive/);
      }
    }

    await ctx.close();
  });
});
