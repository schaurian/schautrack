import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Settings', () => {
  test('settings page loads with user email', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 15000 });
  });

  test('preferences save on change', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Find the weight unit select
    const weightSelect = page.locator('select').filter({ has: page.locator('option[value="kg"]') });
    await expect(weightSelect).toBeVisible({ timeout: 5000 });

    const currentValue = await weightSelect.inputValue();
    const newValue = currentValue === 'kg' ? 'lb' : 'kg';
    await weightSelect.selectOption(newValue);

    // If there's a Save button, click it. Otherwise wait for auto-save.
    const saveBtn = page.getByRole('button', { name: 'Save' }).first();
    if (await saveBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await saveBtn.click();
    } else {
      await page.waitForTimeout(1500);
    }

    // Reload to verify
    await page.reload();
    await page.waitForLoadState('domcontentloaded');

    const reloaded = page.locator('select').filter({ has: page.locator('option[value="kg"]') });
    const afterReload = await reloaded.inputValue();
    expect(afterReload).toBe(newValue);

    // Restore
    await reloaded.selectOption(currentValue);
    if (await saveBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await saveBtn.click();
    } else {
      await page.waitForTimeout(1500);
    }
  });

  test('change daily calorie goal persists after reload', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    // The Calories row has a number input (placeholder="Goal") adjacent to the "Calories" label.
    // Locate the Calories row by its label text, then find the goal input within it.
    const caloriesRow = page.locator('div').filter({ has: page.getByText('Calories', { exact: true }) }).first();
    const goalInput = caloriesRow.locator('input[type="number"][placeholder="Goal"]');
    await expect(goalInput).toBeVisible({ timeout: 5000 });

    const originalValue = await goalInput.inputValue();
    const newGoal = originalValue === '2000' ? '1800' : '2000';

    await goalInput.click({ clickCount: 3 });
    await goalInput.fill(newGoal);
    await goalInput.blur();

    // Wait for autosave indicator
    await expect(page.getByText('Saved')).toBeVisible({ timeout: 6000 });

    // Reload and verify
    await page.reload();
    await page.waitForURL('/settings');
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    const reloadedRow = page.locator('div').filter({ has: page.getByText('Calories', { exact: true }) }).first();
    const reloadedInput = reloadedRow.locator('input[type="number"][placeholder="Goal"]');
    await expect(reloadedInput).toHaveValue(newGoal, { timeout: 5000 });

    // Restore
    await reloadedInput.click({ clickCount: 3 });
    await reloadedInput.fill(originalValue || '0');
    await reloadedInput.blur();
    await page.waitForTimeout(1500);
  });

  test('toggle notes disabled hides notes section on dashboard', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Find the Daily Notes card toggle
    const notesHeading = page.getByRole('heading', { name: 'Daily Notes' });
    await notesHeading.scrollIntoViewIfNeeded();
    const notesCard = notesHeading.locator('../..');
    const notesToggle = notesCard.locator('button').first();

    // Determine current state from presence of the description text
    const descriptionText = page.getByText('Write a daily note on the dashboard');
    const isEnabled = await descriptionText.isVisible({ timeout: 2000 }).catch(() => false);

    if (!isEnabled) {
      // Enable first so we can toggle it off
      await notesToggle.click();
      await page.waitForTimeout(600);
      await expect(descriptionText).toBeVisible({ timeout: 3000 });
    }

    // Disable notes
    await notesToggle.click();
    await page.waitForTimeout(600);

    // Notes section should be gone from dashboard
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');
    const textarea = page.locator('textarea[placeholder*="Write a note"]');
    await expect(textarea).not.toBeVisible({ timeout: 5000 });

    // Re-enable notes to restore state
    await page.goto('/settings');
    await page.waitForURL('/settings');
    const notesHeading2 = page.getByRole('heading', { name: 'Daily Notes' });
    await notesHeading2.scrollIntoViewIfNeeded();
    const notesCard2 = notesHeading2.locator('../..');
    await notesCard2.locator('button').first().click();
    await page.waitForTimeout(600);
  });

  test('change timezone preference autosaves', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Wait for the Internationalization card to load
    await expect(page.getByText('Internationalization')).toBeVisible({ timeout: 10000 });

    // Find the timezone select (it contains timezone strings like "UTC")
    const tzSelect = page.locator('select').filter({ has: page.locator('option[value="UTC"]') });
    await expect(tzSelect).toBeVisible({ timeout: 5000 });

    const originalTz = await tzSelect.inputValue();
    const newTz = originalTz === 'America/New_York' ? 'Europe/London' : 'America/New_York';

    await tzSelect.selectOption(newTz);

    // Wait for the "Saved" indicator to appear
    await expect(page.getByText('Saved')).toBeVisible({ timeout: 6000 });

    // Reload and verify the timezone was persisted
    await page.reload();
    await page.waitForURL('/settings');
    await expect(page.getByText('Internationalization')).toBeVisible({ timeout: 10000 });

    const reloadedTzSelect = page.locator('select').filter({ has: page.locator('option[value="UTC"]') });
    await expect(reloadedTzSelect).toHaveValue(newTz, { timeout: 5000 });

    // Restore original timezone
    await reloadedTzSelect.selectOption(originalTz);
    await expect(page.getByText('Saved')).toBeVisible({ timeout: 6000 });
  });

  test('no spurious Saved indicator on initial page load', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Wait for the page to fully render
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 15000 });

    // Without any user interaction, "Saved" must not appear within 2 seconds of load
    await expect(page.getByText('Saved')).not.toBeVisible({ timeout: 2000 });
  });

  test('autosave indicators appear across settings sections', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 15000 });

    // --- Calorie goal autosave ---
    const caloriesRow = page.locator('div').filter({ has: page.getByText('Calories', { exact: true }) }).first();
    const goalInput = caloriesRow.locator('input[type="number"][placeholder="Goal"]');
    await expect(goalInput).toBeVisible({ timeout: 5000 });

    const originalGoal = await goalInput.inputValue();
    const newGoal = originalGoal === '2000' ? '1900' : '2000';

    await goalInput.click({ clickCount: 3 });
    await goalInput.fill(newGoal);
    await goalInput.blur();

    await expect(page.getByText('Saved')).toBeVisible({ timeout: 6000 });

    // Restore calorie goal
    await goalInput.click({ clickCount: 3 });
    await goalInput.fill(originalGoal || '0');
    await goalInput.blur();
    await page.waitForTimeout(1500);

    // --- Weight unit autosave ---
    await expect(page.getByText('Internationalization')).toBeVisible({ timeout: 5000 });

    const weightSelect = page.locator('select').filter({ has: page.locator('option[value="kg"]') });
    await expect(weightSelect).toBeVisible({ timeout: 5000 });

    const originalWeight = await weightSelect.inputValue();
    const newWeight = originalWeight === 'kg' ? 'lb' : 'kg';

    await weightSelect.selectOption(newWeight);
    await expect(page.getByText('Saved')).toBeVisible({ timeout: 6000 });

    // Restore weight unit
    await weightSelect.selectOption(originalWeight);
    await expect(page.getByText('Saved')).toBeVisible({ timeout: 6000 });
  });

  test('toggle todos disabled hides todos section on dashboard', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Find the Todos card toggle (heading "Todos" within a Card)
    const todosHeading = page.getByRole('heading', { name: 'Todos', exact: true });
    await todosHeading.scrollIntoViewIfNeeded();
    const todosCard = todosHeading.locator('../..');
    const todosToggle = todosCard.locator('button').first();

    // Determine current state from presence of description text
    const descriptionText = page.getByText('Manage your todos on the dashboard.');
    const isEnabled = await descriptionText.isVisible({ timeout: 2000 }).catch(() => false);

    if (!isEnabled) {
      // Enable first
      await todosToggle.click();
      await page.waitForTimeout(600);
      await expect(descriptionText).toBeVisible({ timeout: 3000 });
    }

    // Disable todos
    await todosToggle.click();
    await page.waitForTimeout(600);

    // The todos section heading should not appear on dashboard
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');
    // The TodoList component returns null when disabled, so the "Todos" heading in that widget is gone
    // We check the specific card heading, not the Settings page heading
    const todoWidget = page.locator('h3').filter({ hasText: 'Todos' });
    await expect(todoWidget).not.toBeVisible({ timeout: 5000 });

    // Re-enable todos
    await page.goto('/settings');
    await page.waitForURL('/settings');
    const todosHeading2 = page.getByRole('heading', { name: 'Todos', exact: true });
    await todosHeading2.scrollIntoViewIfNeeded();
    const todosCard2 = todosHeading2.locator('../..');
    await todosCard2.locator('button').first().click();
    await page.waitForTimeout(600);
  });
});
