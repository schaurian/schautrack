import { test, expect } from '@playwright/test';
import { createIsolatedUser } from './fixtures/helpers';
import { chooseOption, selectedValue, expectSelectValue } from './fixtures/select';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

// Settings tests modify user state (timezone, weight unit, macros) and must run serially
// to avoid races between parallel tests that all call savePreferences with different values.
test.describe.serial('Settings', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('settings');
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

  test('settings page loads with preferences', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 15000 });
    await ctx.close();
  });

  test('preferences save on change', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    // Find the weight unit select
    const weightSelect = page.locator('#pref-weight-unit');
    await expect(weightSelect).toBeVisible({ timeout: 5000 });

    const currentValue = await selectedValue(weightSelect);
    const newValue = currentValue === 'kg' ? 'lb' : 'kg';
    await chooseOption(page, weightSelect, newValue);

    // If there's a Save button, click it. Otherwise wait for auto-save.
    // exact: true — role-name matching is substring by default, and 'Save'
    // would otherwise match the "Manage saved foods" button.
    const saveBtn = page.getByRole('button', { name: 'Save', exact: true }).first();
    if (await saveBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await saveBtn.click();
    } else {
      await page.waitForTimeout(1500);
    }

    // Reload to verify
    await page.reload();
    await page.waitForLoadState('domcontentloaded');

    const reloaded = page.locator('#pref-weight-unit');
    const afterReload = await selectedValue(reloaded);
    expect(afterReload).toBe(newValue);

    // Restore
    await chooseOption(page, reloaded, currentValue);
    if (await saveBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await saveBtn.click();
    } else {
      await page.waitForTimeout(1500);
    }

    await ctx.close();
  });

  test('change daily calorie goal persists after reload', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    // The Calories row: find the label containing "Calories" span, go up to its parent row div,
    // then find the goal input sibling. Calories is the first macro row so its goal input is first.
    const goalInput = page.getByPlaceholder('Goal').first();
    await expect(goalInput).toBeVisible({ timeout: 5000 });

    const originalValue = await goalInput.inputValue();
    const newGoal = originalValue === '2000' ? '1800' : '2000';

    await goalInput.click({ clickCount: 3 });
    await goalInput.fill(newGoal);
    await goalInput.blur();

    // Wait for autosave indicator
    await expect(page.getByText('Saved', { exact: true })).toBeVisible({ timeout: 6000 });

    // Reload and verify
    await page.reload();
    await page.waitForURL(/\/settings/);
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 10000 });

    const reloadedInput = page.getByPlaceholder('Goal').first();
    await expect(reloadedInput).toHaveValue(newGoal, { timeout: 5000 });

    // Restore
    await reloadedInput.click({ clickCount: 3 });
    await reloadedInput.fill(originalValue || '0');
    await reloadedInput.blur();
    await page.waitForTimeout(1500);

    await ctx.close();
  });

  test('toggle notes disabled hides notes section on dashboard', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    // Find the Daily Notes card toggle
    const notesHeading = page.getByRole('heading', { name: 'Daily Notes' });
    await notesHeading.scrollIntoViewIfNeeded();
    const notesCard = page.getByTestId('note-settings-card');
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
    await page.goto(`${baseURL}/dashboard`);
    await page.waitForURL(/\/dashboard/);
    const textarea = page.locator('textarea[placeholder*="Write a note"]');
    await expect(textarea).not.toBeVisible({ timeout: 5000 });

    // Re-enable notes to restore state
    await page.goto(`${baseURL}/settings`);
    await page.waitForURL(/\/settings/);
    const notesHeading2 = page.getByRole('heading', { name: 'Daily Notes' });
    await notesHeading2.scrollIntoViewIfNeeded();
    const notesCard2 = page.getByTestId('note-settings-card');
    await notesCard2.locator('button').first().click();
    await page.waitForTimeout(600);

    await ctx.close();
  });

  test('change timezone preference autosaves', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    // Wait for the Internationalization card to load
    await expect(page.getByText('Internationalization')).toBeVisible({ timeout: 10000 });

    // Find the timezone select (it contains timezone strings like "UTC")
    const tzSelect = page.locator('#pref-timezone');
    await expect(tzSelect).toBeVisible({ timeout: 5000 });

    const originalTz = await selectedValue(tzSelect);
    const newTz = originalTz === 'America/New_York' ? 'Europe/London' : 'America/New_York';

    await chooseOption(page, tzSelect, newTz);

    // Wait for the "Saved" indicator to appear
    await expect(page.getByText('Saved', { exact: true })).toBeVisible({ timeout: 6000 });

    // Reload and verify the timezone was persisted
    await page.reload();
    await page.waitForURL(/\/settings/);
    await expect(page.getByText('Internationalization')).toBeVisible({ timeout: 10000 });

    const reloadedTzSelect = page.locator('#pref-timezone');
    await expectSelectValue(reloadedTzSelect, newTz);

    // Restore original timezone
    await chooseOption(page, reloadedTzSelect, originalTz);
    await expect(page.getByText('Saved', { exact: true })).toBeVisible({ timeout: 6000 });

    await ctx.close();
  });

  test('no spurious Saved indicator on initial page load', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    // Wait for the page to fully render
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 15000 });

    // Without any user interaction, "Saved" must not appear within 2 seconds of load
    await expect(page.getByText('Saved', { exact: true })).not.toBeVisible({ timeout: 2000 });

    await ctx.close();
  });

  test('autosave indicators appear across settings sections', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 15000 });

    // --- Calorie goal autosave ---
    // Calories is always the first row so its goal input is the first placeholder="Goal" input
    const goalInput = page.getByPlaceholder('Goal').first();
    await expect(goalInput).toBeVisible({ timeout: 5000 });

    const originalGoal = await goalInput.inputValue();
    const newGoal = originalGoal === '2000' ? '1900' : '2000';

    await goalInput.click({ clickCount: 3 });
    await goalInput.fill(newGoal);
    await goalInput.blur();

    await expect(page.getByText('Saved', { exact: true })).toBeVisible({ timeout: 6000 });

    // Restore calorie goal
    await goalInput.click({ clickCount: 3 });
    await goalInput.fill(originalGoal || '0');
    await goalInput.blur();
    await page.waitForTimeout(1500);

    // --- Weight unit autosave ---
    await expect(page.getByText('Internationalization')).toBeVisible({ timeout: 5000 });

    const weightSelect = page.locator('#pref-weight-unit');
    await expect(weightSelect).toBeVisible({ timeout: 5000 });

    const originalWeight = await selectedValue(weightSelect);
    const newWeight = originalWeight === 'kg' ? 'lb' : 'kg';

    await chooseOption(page, weightSelect, newWeight);
    await expect(page.getByText('Saved', { exact: true })).toBeVisible({ timeout: 6000 });

    // Restore weight unit
    await chooseOption(page, weightSelect, originalWeight);
    await expect(page.getByText('Saved', { exact: true })).toBeVisible({ timeout: 6000 });

    await ctx.close();
  });

  test('toggle todos disabled hides todos section on dashboard', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page, '/settings');

    // Find the Todos card toggle (heading "Todos" within a Card)
    const todosHeading = page.getByRole('heading', { name: 'Todos', exact: true });
    await todosHeading.scrollIntoViewIfNeeded();
    const todosCard = page.getByTestId('todo-settings-card');
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
    await page.goto(`${baseURL}/dashboard`);
    await page.waitForURL(/\/dashboard/);
    // The TodoList component returns null when disabled, so the "Todos" heading in that widget is gone
    // We check the specific card heading, not the Settings page heading
    const todoWidget = page.locator('h3').filter({ hasText: 'Todos' });
    await expect(todoWidget).not.toBeVisible({ timeout: 5000 });

    // Re-enable todos
    await page.goto(`${baseURL}/settings`);
    await page.waitForURL(/\/settings/);
    const todosHeading2 = page.getByRole('heading', { name: 'Todos', exact: true });
    await todosHeading2.scrollIntoViewIfNeeded();
    const todosCard2 = page.getByTestId('todo-settings-card');
    await todosCard2.locator('button').first().click();
    await page.waitForTimeout(600);

    await ctx.close();
  });
});
