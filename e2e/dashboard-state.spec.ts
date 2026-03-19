import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Dashboard State', () => {
  test('calorie panel shows current total', async ({ page }) => {
    await login(page);

    // The calorie panel should be visible with a number
    const calorieValue = page.locator('.text-xl.font-bold.tabular-nums').first();
    await expect(calorieValue).toBeVisible({ timeout: 5000 });

    // Should contain a number
    const text = await calorieValue.textContent();
    expect(text).toMatch(/\d+/);
  });

  test('entry list header shows date and user', async ({ page }) => {
    await login(page);

    // Should show today's date and "You"
    const header = page.locator('h3').filter({ hasText: /\d{4}-\d{2}-\d{2}.*You/ });
    await expect(header).toBeVisible({ timeout: 5000 });
  });

  test('share card shows "You" label', async ({ page }) => {
    await login(page);

    // The user's share card should show "You"
    await expect(page.getByText('You')).toBeVisible({ timeout: 5000 });
  });

  test('today dot has ring indicator', async ({ page }) => {
    await login(page);

    // Today's dot should have a ring (ring-2 class)
    const todayDot = page.locator('button.ring-2');
    await expect(todayDot).toBeVisible({ timeout: 5000 });
  });
});
