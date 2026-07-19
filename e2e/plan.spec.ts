import { test, expect } from '@playwright/test';
import { createIsolatedUser, psql } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe.serial('Weight Planner', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('plan');
  });

  async function loginAndGo(page: import('@playwright/test').Page, path = '/dashboard') {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    if (path !== '/dashboard') {
      await page.goto(`${baseURL}${path}`);
      await page.waitForURL(new RegExp(path), { timeout: 10000 });
    }
  }

  test('happy path: log weight, complete metrics, set a by-rate goal, apply budget', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    // 1. Log today's weight on the dashboard — a goal can't be created until
    //    the server has a latest weight entry to use as the start weight.
    const weightInput = page.locator('input[aria-label="Weight in kg"], input[aria-label="Weight in lb"]');
    await weightInput.scrollIntoViewIfNeeded({ timeout: 5000 });
    await weightInput.fill('130');
    await weightInput.blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 10000 });

    // 2. Go to the planner and complete body metrics.
    await page.goto(`${baseURL}/plan`);
    await page.waitForURL(/\/plan/, { timeout: 10000 });

    await page.locator('label:text-is("Height (cm)") + input').fill('180');
    await page.locator('label:text-is("Birth Year") + input').fill('1986');
    await page.locator('label:text-is("Sex") + select').selectOption('male');
    await page.locator('label:text-is("Activity Level") + select').selectOption('moderate');
    await page.getByRole('button', { name: 'Save Details' }).click();
    await expect(page.getByText('Details saved')).toBeVisible({ timeout: 10000 });

    // 3. Set a goal by rate: 130kg -> 80kg at 0.75 kg/week.
    await page.locator('label:text-is("Target Weight") + span input').fill('80');
    await page.getByRole('button', { name: 'By rate' }).click();
    await page.getByPlaceholder('e.g. 0.5').fill('0.75');
    await page.getByRole('button', { name: 'Save Goal' }).click();
    await expect(page.getByText('Goal saved')).toBeVisible({ timeout: 10000 });

    // 4. A recommended daily budget should appear (~2600 kcal for this profile).
    //    Assert the label + a plausible kcal integer rather than an exact value.
    await expect(page.getByRole('heading', { name: 'Recommended Budget' })).toBeVisible({ timeout: 15000 });
    const budgetLocator = page.getByText(/\d{3,4}\s*kcal\/day/).first();
    await expect(budgetLocator).toBeVisible({ timeout: 15000 });
    const budgetText = await budgetLocator.textContent();
    const match = budgetText?.match(/(\d{3,4})\s*kcal\/day/);
    expect(match, `expected a kcal number in "${budgetText}"`).toBeTruthy();
    expect(Number(match![1])).toBeGreaterThan(2000);

    // 5. Apply the recommended budget as the calorie goal.
    await page.getByRole('button', { name: 'Apply as my calorie goal' }).click();
    await expect(page.getByText('Calorie goal updated')).toBeVisible({ timeout: 10000 });

    // 6. The dashboard PlanCard should now show the weight goal summary.
    await page.goto(`${baseURL}/dashboard`);
    await page.waitForURL(/\/dashboard/, { timeout: 10000 });
    await expect(page.getByRole('heading', { name: 'Weight Goal' })).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(/130\.0\s*kg\s*→\s*80\.0\s*kg/)).toBeVisible({ timeout: 10000 });

    // The calorie goal should have moved off the isolated-user default of 2000.
    const calories = psql(`SELECT macro_goals->>'calories' FROM users WHERE id = ${user.id}`);
    expect(calories).not.toBe('2000');

    await ctx.close();
  });

  test('warns when a target date implies an aggressive pace', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/plan');

    // Same 130 -> 80kg goal, but by date ~2 weeks out — an unsafe rate.
    await page.locator('label:text-is("Target Weight") + span input').fill('80');
    await page.getByRole('button', { name: 'By date' }).click();

    const nearFuture = new Date();
    nearFuture.setDate(nearFuture.getDate() + 14);
    const dateStr = nearFuture.toISOString().slice(0, 10);
    await page.locator('label:text-is("Target Date") + input[type="date"]').fill(dateStr);

    await page.getByRole('button', { name: 'Save Goal' }).click();
    await expect(page.getByText('Goal saved')).toBeVisible({ timeout: 10000 });

    await expect(page.getByText(/faster than 1% of body weight per week/i)).toBeVisible({ timeout: 10000 });

    await ctx.close();
  });
});
