import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { psql } from './fixtures/helpers';

/** Helper: locate the checkbox for a given macro label (e.g. 'Protein'). */
function macroCheckbox(page: import('@playwright/test').Page, label: string) {
  return page.getByText(label, { exact: true }).locator('..').locator('input[type="checkbox"]');
}

/** Helper: wait for the autosave Saved indicator in the Nutrition Goals card. */
async function waitForMacroSaved(page: import('@playwright/test').Page) {
  const saveBtn = page.getByRole('button', { name: 'Save Goals' });
  if (await saveBtn.isVisible({ timeout: 500 }).catch(() => false)) {
    await saveBtn.click();
  }
  // Wait for the green "Saved" text emitted by useAutosave
  await page.waitForTimeout(1200);
}

test.describe('Macro Settings', () => {
  test('toggle macro saves', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 5000 });

    const proteinCheckbox = macroCheckbox(page, 'Protein');
    const wasChecked = await proteinCheckbox.isChecked();

    // Toggle
    await proteinCheckbox.click();

    // If there's a Save Goals button, click it. Otherwise wait for auto-save.
    const saveBtn = page.getByRole('button', { name: 'Save Goals' });
    if (await saveBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await saveBtn.click();
    } else {
      await page.waitForTimeout(2000);
    }

    // Reload and verify
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
    const afterReload = await macroCheckbox(page, 'Protein').isChecked();
    expect(afterReload).toBe(!wasChecked);

    // Restore
    await macroCheckbox(page, 'Protein').click();
    if (await saveBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await saveBtn.click();
    } else {
      await page.waitForTimeout(2000);
    }
  });

  test('disable calories tracking removes calorie input from entry form', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    const caloriesCheckbox = macroCheckbox(page, 'Calories');
    const wasChecked = await caloriesCheckbox.isChecked();

    // Ensure calories is enabled before we disable it
    if (!wasChecked) {
      await caloriesCheckbox.click();
      await waitForMacroSaved(page);
      await page.reload();
      await page.waitForURL('/settings');
      await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });
    }

    // Now disable calories
    await macroCheckbox(page, 'Calories').click();
    await waitForMacroSaved(page);

    // Go to dashboard and verify the calorie input label is gone
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');
    await expect(page.getByText('Calories').first()).not.toBeVisible({ timeout: 5000 });

    // Also confirm the "Calories" label in the entry form is absent
    const caloriesLabel = page.locator('label').filter({ hasText: 'Calories' });
    await expect(caloriesLabel).not.toBeVisible({ timeout: 3000 });

    // Restore: re-enable calories
    await page.goto('/settings');
    await page.waitForURL('/settings');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });
    await macroCheckbox(page, 'Calories').click();
    await waitForMacroSaved(page);
  });

  test.skip('set protein goal with target mode persists after reload', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    // Make sure protein is enabled
    const proteinCb = macroCheckbox(page, 'Protein');
    if (!(await proteinCb.isChecked())) {
      await proteinCb.click();
      await waitForMacroSaved(page);
    }

    // Find the Protein row — locate the goal input within the row containing "Protein"
    const proteinRow = page.locator('div').filter({ has: page.getByText('Protein', { exact: true }) }).first();
    const goalInput = proteinRow.locator('input[type="number"][placeholder="Goal"]');
    await expect(goalInput).toBeVisible({ timeout: 5000 });

    // Set goal to 150
    await goalInput.click({ clickCount: 3 });
    await goalInput.fill('150');

    // Set mode to "Target"
    const modeSelect = proteinRow.locator('select');
    await modeSelect.selectOption('target');

    await waitForMacroSaved(page);

    // Reload and verify
    await page.reload();
    await page.waitForURL('/settings');
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    const reloadedProteinRow = page.locator('div').filter({ has: page.getByText('Protein', { exact: true }) }).first();
    const reloadedGoal = reloadedProteinRow.locator('input[type="number"][placeholder="Goal"]');
    await expect(reloadedGoal).toHaveValue('150', { timeout: 5000 });

    const reloadedMode = reloadedProteinRow.locator('select');
    await expect(reloadedMode).toHaveValue('target', { timeout: 3000 });

    // Restore to neutral
    await reloadedGoal.click({ clickCount: 3 });
    await reloadedGoal.fill('0');
    await reloadedMode.selectOption('limit');
    await waitForMacroSaved(page);
  });

  test.skip('macro totals visible in TodayPanel', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    // Ensure Protein and Carbs are enabled
    const toEnable = ['Protein', 'Carbs'];
    const originalStates: Record<string, boolean> = {};
    for (const label of toEnable) {
      const cb = macroCheckbox(page, label);
      originalStates[label] = await cb.isChecked();
      if (!originalStates[label]) {
        await cb.click();
        await page.waitForTimeout(300);
      }
    }
    await waitForMacroSaved(page);

    // Go to dashboard and add entry with protein=30 carbs=40
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    await page.locator('input[placeholder="Breakfast, snack..."]').fill('TodayPanel Macro Test');

    const calInput = page.locator('input[inputmode="tel"][placeholder="0"]').first();
    if ((await calInput.getAttribute('readonly')) === null) {
      await calInput.fill('300');
    }

    const proteinInput = page.locator('label').filter({ hasText: 'Protein' }).locator('..').locator('input');
    const carbsInput = page.locator('label').filter({ hasText: 'Carbs' }).locator('..').locator('input');
    await expect(proteinInput).toBeVisible({ timeout: 5000 });
    await proteinInput.fill('30');
    await carbsInput.fill('40');

    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // TodayPanel (section with h3 "Today") should show a Protein chip with value 30
    const todaySection = page.locator('section').filter({ has: page.locator('h3', { hasText: 'Today' }) });
    await expect(todaySection).toBeVisible({ timeout: 5000 });

    // The MacroChip for Protein renders the label in uppercase and the total as a bold number
    const proteinChip = todaySection.locator('div').filter({ has: page.getByText('Protein', { exact: true }) }).first();
    await expect(proteinChip).toBeVisible({ timeout: 5000 });
    // The total value is a bold text-xl element; look for "30" inside the chip
    await expect(proteinChip.getByText('30')).toBeVisible({ timeout: 5000 });

    const carbsChip = todaySection.locator('div').filter({ has: page.getByText('Carbs', { exact: true }) }).first();
    await expect(carbsChip).toBeVisible({ timeout: 5000 });
    await expect(carbsChip.getByText('40')).toBeVisible({ timeout: 5000 });

    // Cleanup: delete entry
    const entryRow = page.locator('div').filter({ hasText: 'TodayPanel Macro Test' }).last();
    await entryRow.locator('button[title="Delete"]').click();
    await expect(page.getByText('TodayPanel Macro Test')).not.toBeVisible({ timeout: 5000 });

    // Restore macro states
    await page.goto('/settings');
    await page.waitForURL('/settings');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });
    for (const label of toEnable) {
      if (!originalStates[label]) {
        const cb = macroCheckbox(page, label);
        if (await cb.isChecked()) {
          await cb.click();
          await page.waitForTimeout(300);
        }
      }
    }
    await waitForMacroSaved(page);
  });

  test.skip('macro columns visible in entry list when enabled', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    // Ensure Fat is enabled
    const fatCb = macroCheckbox(page, 'Fat');
    const fatWasChecked = await fatCb.isChecked();
    if (!fatWasChecked) {
      await fatCb.click();
      await waitForMacroSaved(page);
    }

    // Go to dashboard and add entry with fat=15
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    await page.locator('input[placeholder="Breakfast, snack..."]').fill('Entry List Macro Test');

    const calInput = page.locator('input[inputmode="tel"][placeholder="0"]').first();
    if ((await calInput.getAttribute('readonly')) === null) {
      await calInput.fill('200');
    }

    const fatInput = page.locator('label').filter({ hasText: 'Fat' }).locator('..').locator('input');
    await expect(fatInput).toBeVisible({ timeout: 5000 });
    await fatInput.fill('15');

    await page.locator('form button[type="submit"]').click();
    await expect(page.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Find the entry row and verify the Fat macro pill is visible with value 15
    const entryRow = page.locator('div').filter({ hasText: 'Entry List Macro Test' }).last();
    await entryRow.scrollIntoViewIfNeeded({ timeout: 10000 });
    await expect(entryRow).toBeVisible({ timeout: 5000 });

    // MacroPill renders label "Fat" and value "15" inside the pill button
    const fatPill = entryRow.locator('button').filter({ has: page.getByText('Fat', { exact: true }) }).first();
    await expect(fatPill).toBeVisible({ timeout: 5000 });
    await expect(fatPill.getByText('15')).toBeVisible({ timeout: 3000 });

    // Cleanup
    await entryRow.locator('button[title="Delete"]').click();
    await expect(page.getByText('Entry List Macro Test')).not.toBeVisible({ timeout: 5000 });

    // Restore fat state
    if (!fatWasChecked) {
      await page.goto('/settings');
      await page.waitForURL('/settings');
      await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });
      const cb = macroCheckbox(page, 'Fat');
      if (await cb.isChecked()) {
        await cb.click();
        await waitForMacroSaved(page);
      }
    }
  });

  test('auto-calc calories computes value from macros in entry form', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    // Enable calories, protein, carbs, fat (required for auto-calc)
    const toEnable = ['Calories', 'Protein', 'Carbs', 'Fat'];
    const originalStates: Record<string, boolean> = {};
    for (const label of toEnable) {
      const cb = macroCheckbox(page, label);
      originalStates[label] = await cb.isChecked();
      if (!originalStates[label]) {
        await cb.click();
        await page.waitForTimeout(300);
      }
    }
    await waitForMacroSaved(page);

    // After enabling all four, the "Auto-calculate calories" checkbox should appear
    const autoCalcCb = page.getByText('Auto-calculate calories').locator('..').locator('input[type="checkbox"]');
    await expect(autoCalcCb).toBeVisible({ timeout: 5000 });

    const wasAutoCalcChecked = await autoCalcCb.isChecked();
    if (!wasAutoCalcChecked) {
      await autoCalcCb.click();
      await waitForMacroSaved(page);
    }

    // Reload to confirm auto-calc is saved
    await page.reload();
    await page.waitForURL('/settings');
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('Auto-calculate calories').locator('..').locator('input[type="checkbox"]')).toBeChecked({ timeout: 5000 });

    // Go to dashboard and fill in protein=10, carbs=20, fat=5
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    // Protein input: label is "Protein" (uppercase in the form)
    const proteinInput = page.locator('label').filter({ hasText: 'Protein' }).locator('..').locator('input');
    const carbsInput = page.locator('label').filter({ hasText: 'Carbs' }).locator('..').locator('input');
    const fatInput = page.locator('label').filter({ hasText: 'Fat' }).locator('..').locator('input');
    const caloriesInput = page.locator('label').filter({ hasText: 'Calories' }).locator('..').locator('input');

    await expect(proteinInput).toBeVisible({ timeout: 10000 });
    await proteinInput.fill('10');
    await carbsInput.fill('20');
    await fatInput.fill('5');

    // Expected: 10*4 + 20*4 + 5*9 = 40 + 80 + 45 = 165
    await expect(caloriesInput).toHaveValue('165', { timeout: 3000 });

    // Restore: go back to settings and disable auto-calc + revert macros
    await page.goto('/settings');
    await page.waitForURL('/settings');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    if (!wasAutoCalcChecked) {
      const autoCalcCb2 = page.getByText('Auto-calculate calories').locator('..').locator('input[type="checkbox"]');
      if (await autoCalcCb2.isVisible({ timeout: 1000 }).catch(() => false)) {
        await autoCalcCb2.click();
        await page.waitForTimeout(300);
      }
    }
    // Restore macros that were originally disabled
    for (const label of toEnable) {
      if (!originalStates[label]) {
        const cb = macroCheckbox(page, label);
        if (await cb.isChecked()) {
          await cb.click();
          await page.waitForTimeout(300);
        }
      }
    }
    await waitForMacroSaved(page);
  });
});
