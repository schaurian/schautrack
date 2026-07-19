import { test, expect, Page } from '@playwright/test';
import { createIsolatedUser, psql } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe.serial('Weight Planner', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('plan');
    // createIsolatedUser does not know about the planner tables/columns, so
    // reset them here for deterministic reruns: no goal, no body metrics, and
    // the default 2000 kcal calorie goal.
    psql(`DELETE FROM weight_goals WHERE user_id = ${user.id}`);
    psql(`UPDATE users SET height_cm = NULL, birth_year = NULL, sex = NULL, activity_level = NULL,
          macro_goals = jsonb_set(COALESCE(macro_goals, '{}'::jsonb), '{calories}', '2000') WHERE id = ${user.id}`);
  });

  async function login(page: Page) {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
  }

  async function gotoPlan(page: Page) {
    await page.goto(`${baseURL}/plan`);
    await page.waitForURL(/\/plan/, { timeout: 10000 });
    // Wait for the ['plan'] query to resolve and the page to render (not the
    // loading spinner) before interacting.
    await expect(page.getByRole('heading', { name: 'Goal Setup' })).toBeVisible({ timeout: 15000 });
  }

  test('happy path: log weight, complete metrics, set a by-rate goal, apply budget', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);

    // 1. Log today's weight — a goal needs a latest weight entry as its start.
    const weightInput = page.locator('input[aria-label="Weight in kg"], input[aria-label="Weight in lb"]');
    await weightInput.scrollIntoViewIfNeeded({ timeout: 5000 });
    await weightInput.fill('130');
    await weightInput.blur();
    await expect(page.getByText('Weight tracked')).toBeVisible({ timeout: 10000 });

    // 2. Complete body metrics on the planner. Fresh user => "Your Details" is
    //    expanded; wait for the height field before filling.
    await gotoPlan(page);
    const heightInput = page.locator('label:text-is("Height (cm)") + input');
    await expect(heightInput).toBeVisible({ timeout: 10000 });
    await heightInput.fill('180');
    await page.locator('label:text-is("Birth Year") + input').fill('1986');
    await page.locator('label:text-is("Sex") + select').selectOption('male');
    await page.locator('label:text-is("Activity Level") + select').selectOption('moderate');
    await page.getByRole('button', { name: 'Save Details' }).click();
    await expect(page.getByText('Details saved')).toBeVisible({ timeout: 10000 });

    // 3. Set a by-rate goal: 130kg -> 80kg at 0.75 kg/week.
    await page.locator('label:text-is("Target Weight") + span input').fill('80');
    await page.getByRole('button', { name: 'By rate' }).click();
    const rateInput = page.getByPlaceholder('e.g. 0.5');
    await expect(rateInput).toBeVisible({ timeout: 10000 });
    await rateInput.fill('0.75');
    await page.getByRole('button', { name: 'Save Goal' }).click();
    await expect(page.getByText('Goal saved')).toBeVisible({ timeout: 10000 });

    // 4. A recommended daily budget should appear (~2600 kcal for this profile).
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

    // 6. The dashboard PlanCard should now show the weight-goal summary.
    await page.goto(`${baseURL}/dashboard`);
    await page.waitForURL(/\/dashboard/, { timeout: 10000 });
    await expect(page.getByRole('heading', { name: 'Weight Goal' })).toBeVisible({ timeout: 10000 });
    await expect(page.getByText(/130\.0\s*kg\s*→\s*80\.0\s*kg/)).toBeVisible({ timeout: 10000 });

    // Calorie goal should have moved off the isolated-user default of 2000.
    const calories = psql(`SELECT macro_goals->>'calories' FROM users WHERE id = ${user.id}`);
    expect(calories).not.toBe('2000');

    await ctx.close();
  });

  test('warns when a target date implies an aggressive pace', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);
    await gotoPlan(page); // metrics are already complete from the previous test

    // 130 -> 80kg by a date ~2 weeks out is a wildly unsafe pace.
    await page.locator('label:text-is("Target Weight") + span input').fill('80');
    await page.getByRole('button', { name: 'By date' }).click();
    const dateInput = page.locator('label:text-is("Target Date") + input[type="date"]');
    await expect(dateInput).toBeVisible({ timeout: 10000 });
    const nearFuture = new Date();
    nearFuture.setDate(nearFuture.getDate() + 14);
    const dateStr = nearFuture.toISOString().slice(0, 10);
    await dateInput.fill(dateStr);
    // The date field is a controlled input — assert React state actually took
    // the value (otherwise handleSave's "Choose a target date" guard returns
    // before saving).
    await expect(dateInput).toHaveValue(dateStr);

    await page.getByRole('button', { name: 'Save Goal' }).click();
    await expect(page.getByText('Goal saved')).toBeVisible({ timeout: 10000 });

    // The aggressive-pace warning is the real behavioral signal that the goal
    // saved and the server recomputed the plan.
    await expect(page.getByText(/faster than 1% of body weight per week/i)).toBeVisible({ timeout: 15000 });

    await ctx.close();
  });
});
