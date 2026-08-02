import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Dashboard State', () => {
  test('calorie panel shows current total', async ({ page }) => {
    await login(page);

    // The calories ring should be visible with a number in its center
    const kcalRing = page.getByRole('img', { name: /^Calories:/ }).first();
    await expect(kcalRing).toBeVisible({ timeout: 5000 });

    // Should contain a number
    const text = await kcalRing.textContent();
    expect(text).toMatch(/\d+/);
  });

  test('entry list header shows date and user', async ({ page }) => {
    await login(page);

    // The entries header span should show today's date and "You"
    const header = page.locator('span').filter({ hasText: /\d{4}-\d{2}-\d{2}.*You/ });
    await expect(header).toBeVisible({ timeout: 5000 });
  });

  test('share card shows "You" label', async ({ page }) => {
    await login(page);

    // The user's share card should show "You"
    await expect(page.getByText('You', { exact: true })).toBeVisible({ timeout: 5000 });
  });

  test('today dot has ring indicator', async ({ page }) => {
    await login(page);

    // Today's dot should have a ring (ring-2 class)
    const todayDot = page.locator('button.ring-2');
    await expect(todayDot).toBeVisible({ timeout: 5000 });
  });
});
