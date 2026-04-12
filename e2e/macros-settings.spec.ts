import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

/** Helper: locate the checkbox for a given macro label (e.g. 'Protein'). */
function macroCheckbox(page: import('@playwright/test').Page, label: string) {
  return page.getByText(label, { exact: true }).locator('..').locator('input[type="checkbox"]');
}

/**
 * Helper: trigger a macro save and wait for the API response.
 * MUST be called with a promise set up BEFORE the triggering action, e.g.:
 *   await triggerAndWaitForMacroSave(page, () => checkbox.click());
 */
async function triggerAndWaitForMacroSave(
  page: import('@playwright/test').Page,
  action: () => Promise<void>
) {
  const saveBtn = page.getByRole('button', { name: 'Save Goals' });
  const hasSaveBtn = await saveBtn.isVisible({ timeout: 500 }).catch(() => false);

  if (hasSaveBtn) {
    // Manual save mode: run action then click save
    await action();
    await saveBtn.click();
    await page.waitForResponse(
      resp => resp.url().includes('/settings/macros') && resp.request().method() === 'POST',
      { timeout: 8000 }
    );
  } else {
    // Auto-save mode: set up response listener BEFORE action so we don't miss it
    const responsePromise = page.waitForResponse(
      resp => resp.url().includes('/settings/macros') && resp.request().method() === 'POST',
      { timeout: 8000 }
    );
    await action();
    await responsePromise;
  }
}

/** @deprecated use triggerAndWaitForMacroSave for new code */
async function waitForMacroSaved(page: import('@playwright/test').Page) {
  await page.waitForTimeout(2500);
}

test.describe.serial('Macro Settings', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('macros');
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

  test('toggle macro saves', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 5000 });

    const proteinCheckbox = macroCheckbox(page, 'Protein');
    const wasChecked = await proteinCheckbox.isChecked();

    // Toggle and wait for save to complete
    await triggerAndWaitForMacroSave(page, () => proteinCheckbox.click());

    // Reload and verify
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });
    const afterReload = await macroCheckbox(page, 'Protein').isChecked();
    expect(afterReload).toBe(!wasChecked);

    // Restore
    await triggerAndWaitForMacroSave(page, () => macroCheckbox(page, 'Protein').click());

    await ctx.close();
  });

  test('disable calories tracking removes calorie input from entry form', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    const caloriesCheckbox = macroCheckbox(page, 'Calories');
    const wasChecked = await caloriesCheckbox.isChecked();

    // Ensure calories is enabled before we disable it
    if (!wasChecked) {
      await triggerAndWaitForMacroSave(page, () => caloriesCheckbox.click());
      await page.reload();
      await page.waitForURL(/\/settings/);
      await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });
    }

    // Now disable calories
    await triggerAndWaitForMacroSave(page, () => macroCheckbox(page, 'Calories').click());

    // Go to dashboard and verify the calorie input label is gone
    await page.goto(`${baseURL}/dashboard`);
    await page.waitForURL(/\/dashboard/);
    await expect(page.getByText('Calories').first()).not.toBeVisible({ timeout: 5000 });

    // Also confirm the "Calories" label in the entry form is absent
    const caloriesLabel = page.locator('label').filter({ hasText: 'Calories' });
    await expect(caloriesLabel).not.toBeVisible({ timeout: 3000 });

    // Restore: re-enable calories
    await page.goto(`${baseURL}/settings`);
    await page.waitForURL(/\/settings/);
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });
    await triggerAndWaitForMacroSave(page, () => macroCheckbox(page, 'Calories').click());

    await ctx.close();
  });

  test('set protein goal with target mode persists after reload', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    // Make sure protein is enabled
    const proteinCb = macroCheckbox(page, 'Protein');
    if (!(await proteinCb.isChecked())) {
      await triggerAndWaitForMacroSave(page, () => proteinCb.click());
    }

    // Find the Protein row — locate the goal input within the row containing "Protein"
    const proteinRow = page.locator('label').filter({ hasText: 'Protein' }).locator('..');
    const goalInput = proteinRow.locator('input[type="number"][placeholder="Goal"]');
    await expect(goalInput).toBeVisible({ timeout: 5000 });

    // Set goal to 150 and mode to "Target", then wait for autosave
    await triggerAndWaitForMacroSave(page, async () => {
      await goalInput.click({ clickCount: 3 });
      await goalInput.fill('150');
      const modeSelect = proteinRow.locator('select');
      await modeSelect.selectOption('target');
    });

    // Reload and verify
    await page.reload();
    await page.waitForURL(/\/settings/);
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    const reloadedProteinRow = page.locator('label').filter({ hasText: 'Protein' }).locator('..');
    const reloadedGoal = reloadedProteinRow.locator('input[type="number"][placeholder="Goal"]');
    await expect(reloadedGoal).toHaveValue('150', { timeout: 5000 });

    const reloadedMode = reloadedProteinRow.locator('select');
    await expect(reloadedMode).toHaveValue('target', { timeout: 3000 });

    // Restore to neutral
    await triggerAndWaitForMacroSave(page, async () => {
      await reloadedGoal.click({ clickCount: 3, force: true });
      await reloadedGoal.fill('0', { force: true });
      await reloadedMode.selectOption('limit', { force: true });
    });

    await ctx.close();
  });

  test('auto-calc calories computes value from macros in entry form', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    // Enable calories, protein, carbs, fat (required for auto-calc)
    const toEnable = ['Calories', 'Protein', 'Carbs', 'Fat'];
    const originalStates: Record<string, boolean> = {};
    let anyEnabled = false;
    for (const label of toEnable) {
      const cb = macroCheckbox(page, label);
      originalStates[label] = await cb.isChecked();
      if (!originalStates[label]) {
        anyEnabled = true;
      }
    }
    if (anyEnabled) {
      await triggerAndWaitForMacroSave(page, async () => {
        for (const label of toEnable) {
          if (!originalStates[label]) {
            await macroCheckbox(page, label).click();
            await page.waitForTimeout(100);
          }
        }
      });
    }

    // After enabling all four, the "Auto-calculate calories" checkbox should appear
    const autoCalcCb = page.getByText('Auto-calculate calories').locator('..').locator('input[type="checkbox"]');
    await expect(autoCalcCb).toBeVisible({ timeout: 5000 });

    const wasAutoCalcChecked = await autoCalcCb.isChecked();
    if (!wasAutoCalcChecked) {
      await triggerAndWaitForMacroSave(page, () => autoCalcCb.click());
    }

    // Reload to confirm auto-calc is saved
    await page.reload();
    await page.waitForURL(/\/settings/);
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Auto-calculate calories').locator('..').locator('input[type="checkbox"]')).toBeChecked({ timeout: 5000 });

    // Go to dashboard and fill in protein=10, carbs=20, fat=5
    await page.goto(`${baseURL}/dashboard`);
    await page.waitForURL(/\/dashboard/);

    // Macro inputs use inputmode="numeric"; calories auto-calc field is readonly with inputmode="tel"
    const proteinInput = page.locator('label').filter({ hasText: 'Protein' }).locator('..').locator('input[inputmode="numeric"]');
    const carbsInput = page.locator('label').filter({ hasText: 'Carbs' }).locator('..').locator('input[inputmode="numeric"]');
    const fatInput = page.locator('label').filter({ hasText: 'Fat' }).locator('..').locator('input[inputmode="numeric"]');
    const caloriesInput = page.locator('label').filter({ hasText: 'Calories' }).locator('..').locator('input[inputmode="tel"]');

    await expect(proteinInput).toBeVisible({ timeout: 10000 });
    await proteinInput.click();
    await proteinInput.pressSequentially('10');
    await carbsInput.click();
    await carbsInput.pressSequentially('20');
    await fatInput.click();
    await fatInput.pressSequentially('5');

    // Expected: 10*4 + 20*4 + 5*9 = 40 + 80 + 45 = 165
    await expect(caloriesInput).toHaveValue('165', { timeout: 5000 });

    // Restore: go back to settings and disable auto-calc + revert macros
    await page.goto(`${baseURL}/settings`);
    await page.waitForURL(/\/settings/);
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    // Restore auto-calc and macros
    await triggerAndWaitForMacroSave(page, async () => {
      if (!wasAutoCalcChecked) {
        const autoCalcCb2 = page.getByText('Auto-calculate calories').locator('..').locator('input[type="checkbox"]');
        if (await autoCalcCb2.isVisible({ timeout: 1000 }).catch(() => false)) {
          await autoCalcCb2.click();
          await page.waitForTimeout(100);
        }
      }
      for (const label of toEnable) {
        if (!originalStates[label]) {
          const cb = macroCheckbox(page, label);
          if (await cb.isChecked()) {
            await cb.click();
            await page.waitForTimeout(100);
          }
        }
      }
    });

    await ctx.close();
  });
});
