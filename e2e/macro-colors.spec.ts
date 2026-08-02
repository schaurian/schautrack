import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser } from './fixtures/helpers';

// TodayPanel renders calories as an SVG progress ring (components/ui/Ring.tsx)
// and each macro as a glowing bar (Dashboard/TodayPanel.tsx MacroBar).
// Both are colored from MacroStatus via lib/ring.ts ringColor():
//   macro-stat--success → #22c55e (green)
//   macro-stat--warning → #f59e0b (amber)
//   macro-stat--danger  → #ef4444 (red)
// Both wrappers are <div role="img" aria-label="<Label>: <value> / <goal> <unit>">.
//   Ring: contains an <svg> with circle[0]=track and circle[1]=progress (stroke).
//   MacroBar: contains a track div wrapping a fill div whose inline style sets
//             `background` (and a matching box-shadow glow) to the status color.

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

  test('target mode: over goal shows success/green fill on the protein bar', async ({ browser }) => {
    // Insert entry directly to guarantee protein=120 is recorded (avoids form input fragility)
    psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, protein_g, entry_name)
          VALUES (${targetUser.id}, '${TODAY}', 500, 120, 'High protein meal')`);

    const { context: ctx, page } = await loginUser(browser, targetUser.email, targetUser.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // Wait for the protein bar to render with the value (120 of goal 100)
    const proteinBar = page.getByRole('img', { name: /^Protein:/ }).first();
    await expect(proteinBar).toBeVisible({ timeout: 10000 });
    await expect(proteinBar).toHaveAttribute('aria-label', /^Protein: 120 \/ 100 g$/, { timeout: 8000 });

    // In target mode, protein=120 >= goal=100 → success → green bar fill
    const proteinFill = proteinBar.locator('div[style*="background"]');
    await expect(proteinFill).toBeVisible();
    await expect(proteinFill).toHaveCSS('background-color', 'rgb(34, 197, 94)'); // #22c55e

    await ctx.close();
  });

  test('limit mode: over goal shows destructive/red styling on calories ring', async ({ browser }) => {
    // Insert entry directly for reliable calorie tracking
    psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name)
          VALUES (${limitUser.id}, '${TODAY}', 1200, 'Over limit meal')`);

    const { context: ctx, page } = await loginUser(browser, limitUser.email, limitUser.password);
    await page.goto('/dashboard');
    await page.waitForLoadState('domcontentloaded');

    // Wait for the calories ring with the value
    const kcalRing = page.getByRole('img', { name: /^Calories:/ }).first();
    await expect(kcalRing).toBeVisible({ timeout: 10000 });
    await expect(kcalRing.getByText('1200')).toBeVisible({ timeout: 8000 });

    // In limit mode, calories=1200 > goal=1000 → danger → red ring
    const kcalStroke = await kcalRing.locator('circle').nth(1).getAttribute('stroke');
    expect(kcalStroke).toBe('#ef4444');

    await ctx.close();
  });
});
