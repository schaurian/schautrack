import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser } from './fixtures/helpers';

// TodayPanel chip status classes (from TodayPanel.tsx statusClasses()):
//   macro-stat--success → bg-success/10 border-success/35  (target mode: at/over goal = green)
//   macro-stat--warning → bg-warning/10 border-warning/35  (limit mode: close to goal = yellow)
//   macro-stat--danger  → bg-destructive/10 border-destructive/35 (limit mode: over goal = red)

const TODAY = new Date().toLocaleDateString('en-CA', { timeZone: 'UTC' });

let targetUser: { email: string; password: string; id: string };
let limitUser: { email: string; password: string; id: string };

test.describe('Macro Status Colors', () => {
  test.beforeAll(() => {
    // User with protein in "target" mode, goal = 100
    targetUser = createIsolatedUser('macro-colors-target');
    psql(`UPDATE users SET
      macros_enabled = '{"calories": true, "protein": true, "carbs": false, "fat": false, "fiber": false, "sugar": false, "auto_calc_calories": false}',
      macro_goals = '{"calories": 2000, "protein": 100, "carbs": 0, "fat": 0, "fiber": 0, "sugar": 0, "calories_mode": "limit", "protein_mode": "target", "carbs_mode": "limit", "fat_mode": "limit"}',
      daily_goal = 2000
      WHERE id = ${targetUser.id}`);

    // User with calories in "limit" mode, goal = 1000
    limitUser = createIsolatedUser('macro-colors-limit');
    psql(`UPDATE users SET
      macros_enabled = '{"calories": true, "protein": false, "carbs": false, "fat": false, "fiber": false, "sugar": false, "auto_calc_calories": false}',
      macro_goals = '{"calories": 1000, "protein": 0, "carbs": 0, "fat": 0, "fiber": 0, "sugar": 0, "calories_mode": "limit", "protein_mode": "limit", "carbs_mode": "limit", "fat_mode": "limit"}',
      daily_goal = 1000
      WHERE id = ${limitUser.id}`);
  });

  test.afterAll(() => {
    psql(`DELETE FROM calorie_entries WHERE user_id = ${targetUser.id}`);
    psql(`DELETE FROM calorie_entries WHERE user_id = ${limitUser.id}`);
  });

  test('target mode: over goal shows success/green styling on protein chip', async ({ browser }) => {
    // Insert entry directly to guarantee protein=120 is recorded (avoids form input fragility)
    psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, protein_g, entry_name)
          VALUES (${targetUser.id}, '${TODAY}', 500, 120, 'High protein meal')`);

    const { context: ctx, page } = await loginUser(browser, targetUser.email, targetUser.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // Wait for the TodayPanel to render with data
    const todayPanel = page.locator('section.rounded-xl').filter({ hasText: 'Today' }).first();
    await expect(todayPanel).toBeVisible({ timeout: 10000 });

    // Wait for protein chip to show the value (120)
    await expect(todayPanel.getByText('120')).toBeVisible({ timeout: 8000 });

    // The Protein label is in a div inside the chip div:
    //   <div class="rounded-xl border p-3 transition-colors {statusClasses}">   ← chipDiv
    //     <div class="text-xs font-bold uppercase ...">Protein</div>             ← labelDiv (one level up from text)
    //   </div>
    const proteinLabel = todayPanel.getByText('Protein', { exact: true }).first();
    await expect(proteinLabel).toBeVisible({ timeout: 8000 });

    // labelDiv.locator('..') = chipDiv
    const chipDiv = proteinLabel.locator('..');
    const chipClass = await chipDiv.getAttribute('class');

    // In target mode, protein=120 >= goal=100 → success (green)
    if (chipClass) {
      expect(chipClass).toMatch(/success/);
      expect(chipClass).not.toMatch(/destructive/);
    }

    await ctx.close();
  });

  test('limit mode: over goal shows destructive/red styling on calories chip', async ({ browser }) => {
    // Insert entry directly for reliable calorie tracking
    psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name)
          VALUES (${limitUser.id}, '${TODAY}', 1200, 'Over limit meal')`);

    const { context: ctx, page } = await loginUser(browser, limitUser.email, limitUser.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // Wait for TodayPanel with the calorie value
    const todayPanel = page.locator('section.rounded-xl').filter({ hasText: 'Today' }).first();
    await expect(todayPanel).toBeVisible({ timeout: 10000 });
    await expect(todayPanel.getByText('1200')).toBeVisible({ timeout: 8000 });

    const caloriesLabel = todayPanel.getByText('Calories', { exact: true }).first();
    await expect(caloriesLabel).toBeVisible({ timeout: 8000 });

    // labelDiv.locator('..') = chipDiv
    const chipDiv = caloriesLabel.locator('..');
    const chipClass = await chipDiv.getAttribute('class');

    // In limit mode, calories=1200 > goal=1000 → destructive (red)
    if (chipClass) {
      expect(chipClass).toMatch(/destructive/);
    }

    await ctx.close();
  });
});
