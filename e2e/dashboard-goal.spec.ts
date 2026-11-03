import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser, loginUser } from './fixtures/helpers';

/**
 * Goal onboarding and remaining/over feedback on your own dashboard.
 *
 * A new account used to finish the welcome tour on a bare "0 calories" ring
 * with no goal and no hint where to set one, and the ring read "1720 / 2200"
 * without ever saying "480 left".
 */

const TODAY = new Date().toLocaleDateString('en-CA', { timeZone: 'UTC' });

let user: { email: string; password: string; id: string };

test.describe('Dashboard goal feedback', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('dashboard-goal', { features: false });
  });

  test.afterAll(() => {
    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id}`);
  });

  test('the tour ends on "Set your goal", which opens Settings', async ({ browser }) => {
    // A never-onboarded account with calories on and no calorie goal.
    psql(`UPDATE users SET onboarding_completed_at = NULL, daily_goal = NULL,
      macros_enabled = '{"calories": true}', macro_goals = '{}' WHERE id = ${user.id}`);
    const { context, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');

    const tour = page.getByTestId('welcome-tour');
    await expect(tour).toBeVisible({ timeout: 10000 });
    for (let step = 2; step <= 5; step++) {
      await page.getByTestId('welcome-tour-next').click();
      await expect(tour.getByText(`${step} of 5`)).toBeVisible();
    }
    await page.getByTestId('welcome-tour-set-goal').click();
    await page.waitForURL(/\/settings/);
    await expect(tour).toHaveCount(0);
    expect(psql(`SELECT onboarding_completed_at IS NOT NULL FROM users WHERE id = ${user.id}`)).toBe('t');

    // Still no goal, so the dashboard keeps nudging.
    await page.goto('/dashboard');
    await expect(page.getByTestId('goal-prompt')).toBeVisible({ timeout: 10000 });
    await context.close();
  });

  test('your own dashboard shows calories and macros left, then over', async ({ browser }) => {
    psql(`UPDATE users SET onboarding_completed_at = now(),
      macros_enabled = '{"calories": true, "protein": true, "carbs": false, "fat": false, "fiber": false, "sugar": false, "auto_calc_calories": false}',
      macro_goals = '{"calories": 2200, "protein": 110, "calories_mode": "limit", "protein_mode": "limit"}',
      daily_goal = 2200 WHERE id = ${user.id}`);
    psql(`DELETE FROM calorie_entries WHERE user_id = ${user.id};
      INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name, protein_g)
      VALUES (${user.id}, '${TODAY}', 1720, 'lunch', 86)`);
    const { context, page } = await loginUser(browser, user.email, user.password);
    await page.goto('/dashboard');

    await expect(page.getByTestId('calorie-delta')).toHaveText('480 left', { timeout: 10000 });
    await expect(page.getByTestId('macro-delta-protein')).toHaveText('24 left');
    await expect(page.getByTestId('macro-goal-marker-protein')).toHaveCount(0);
    await expect(page.getByTestId('goal-prompt')).toHaveCount(0);

    psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name, protein_g)
      VALUES (${user.id}, '${TODAY}', 780, 'dinner', 48)`);
    await page.reload();
    await expect(page.getByTestId('calorie-delta')).toHaveText('+300 over', { timeout: 10000 });
    await expect(page.getByTestId('macro-delta-protein')).toHaveText('+24 over');
    await expect(page.getByTestId('macro-goal-marker-protein')).toBeVisible();
    await context.close();
  });
});
