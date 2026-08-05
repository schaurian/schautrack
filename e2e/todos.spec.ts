import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe.serial('Todos', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('todos');
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

  test('create, complete, and delete a todo', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    // Todos section should be on the dashboard
    const todosHeading = page.getByText('Todos', { exact: true });
    await todosHeading.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(todosHeading).toBeVisible();

    // Click "Add a todo" to open the manager with add form
    await page.getByText('Add a todo').click();

    // Fill in todo name and submit
    const nameInput = page.locator('input[placeholder="Todo name"]');
    await expect(nameInput).toBeVisible({ timeout: 5000 });
    await nameInput.fill('E2E Test Todo');
    await page.getByRole('button', { name: 'Add', exact: true }).click();

    // Close manager
    await page.getByRole('button', { name: 'Done' }).last().click();

    // Todo should appear in the list
    await expect(page.getByText('E2E Test Todo')).toBeVisible({ timeout: 5000 });

    // Toggle complete (checkbox on the right)
    const todoRow = page.locator('li').filter({ hasText: 'E2E Test Todo' });
    const checkbox = todoRow.locator('button, input[type="checkbox"]').last();
    await checkbox.click();
    await expect(todoRow.locator('.line-through')).toBeVisible({ timeout: 3000 });

    // Open Edit to delete
    await page.getByRole('button', { name: 'Edit' }).first().click();

    // Find "Remove" button for our todo in the manager
    await page.getByRole('button', { name: 'Remove' }).click();

    // Close manager
    await page.getByRole('button', { name: 'Done' }).last().click();

    // Todo should be gone
    await expect(page.getByText('E2E Test Todo')).not.toBeVisible({ timeout: 5000 });

    await ctx.close();
  });

  test('edit todo name persists after reload', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    // Open the manager via the Edit button (there should be at least one todo, or create one)
    const todosSection = page.locator('div').filter({ has: page.getByText('Todos', { exact: true }) }).first();
    await todosSection.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => {});

    // If there are no todos, create one first
    const addTodoBtn = page.getByText('Add a todo');
    const editBtn = page.getByRole('button', { name: 'Edit' }).first();
    const hasAddBtn = await addTodoBtn.isVisible({ timeout: 2000 }).catch(() => false);

    if (hasAddBtn) {
      await addTodoBtn.click();
      const nameInput = page.locator('input[placeholder="Todo name"]');
      await expect(nameInput).toBeVisible({ timeout: 5000 });
      await nameInput.fill('Todo To Edit');
      await page.getByRole('button', { name: 'Add', exact: true }).click();
      // Close the manager so the todo appears in the regular list
      await page.getByRole('button', { name: 'Done' }).last().click();
    } else {
      await editBtn.click();
      // Add a todo from within manager if list is empty
      const addTodoInManager = page.getByRole('button', { name: 'Add todo' });
      const hasAddInManager = await addTodoInManager.isVisible({ timeout: 1000 }).catch(() => false);
      if (hasAddInManager) {
        await addTodoInManager.click();
        const nameInput = page.locator('input[placeholder="Todo name"]');
        await nameInput.fill('Todo To Edit');
        await page.getByRole('button', { name: 'Add', exact: true }).click();
      }
      await page.getByRole('button', { name: 'Done' }).last().click();
    }

    // Wait for todo to appear in list
    await expect(page.getByText('Todo To Edit')).toBeVisible({ timeout: 5000 });

    // Open the manager and click Edit on the specific todo
    await page.getByRole('button', { name: 'Edit' }).first().click();

    const todoManagerRow = page.locator('li').filter({ hasText: 'Todo To Edit' });
    await expect(todoManagerRow).toBeVisible({ timeout: 5000 });
    await todoManagerRow.getByRole('button', { name: 'Edit' }).click();

    // After clicking Edit, the inline edit form appears — the li now shows an input instead of the text.
    // Use a page-level selector to find the edit input (not scoped to the row, since hasText won't
    // match an input's value).
    const editInput = page.locator('input[maxlength="100"]').first();
    await expect(editInput).toBeVisible({ timeout: 5000 });
    await editInput.fill('Renamed Todo');
    await page.getByRole('button', { name: 'Save', exact: true }).first().click();

    // Close manager
    await page.getByRole('button', { name: 'Done' }).last().click();

    // Should see the renamed todo in the list
    await expect(page.getByText('Renamed Todo')).toBeVisible({ timeout: 5000 });

    // Reload and verify persistence
    await page.reload();
    await page.waitForURL(/\/dashboard/);
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByText('Renamed Todo')).toBeVisible({ timeout: 10000 });

    // Clean up: delete the renamed todo
    await page.getByRole('button', { name: 'Edit' }).first().click();
    const renamedRow = page.locator('li').filter({ hasText: 'Renamed Todo' });
    await renamedRow.getByRole('button', { name: 'Remove' }).click();
    await page.getByRole('button', { name: 'Done' }).last().click();

    await ctx.close();
  });

  test('todo with specific weekdays shows schedule in manager', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    // Open manager — if no todos yet, we need the Edit button to be visible
    const addTodoBtn = page.getByText('Add a todo');
    const hasAddBtn = await addTodoBtn.isVisible({ timeout: 2000 }).catch(() => false);

    if (hasAddBtn) {
      await addTodoBtn.click();
    } else {
      await page.getByRole('button', { name: 'Edit' }).first().click();
      await page.getByRole('button', { name: 'Add todo' }).click();
    }

    // Fill the name
    const nameInput = page.locator('input[placeholder="Todo name"]');
    await expect(nameInput).toBeVisible({ timeout: 5000 });
    await nameInput.fill('Weekday Todo');

    // Switch to "Specific days" schedule
    const specificDaysRadio = page.getByLabel('Specific days');
    await specificDaysRadio.click();

    // Default is Mon–Fri selected; deselect Tue, Thu, Fri to leave Mon and Wed
    await page.getByRole('button', { name: 'Tue' }).click();
    await page.getByRole('button', { name: 'Thu' }).click();
    await page.getByRole('button', { name: 'Fri' }).click();
    // Mon and Wed should now be selected

    await page.getByRole('button', { name: 'Add', exact: true }).click();

    // Close manager (Done button)
    const doneBtn = page.getByRole('button', { name: 'Done' });
    if (await doneBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await doneBtn.last().click();
    }

    // Open manager again to verify schedule text
    await page.getByRole('button', { name: 'Edit' }).first().click();
    const weekdayRow = page.locator('li').filter({ hasText: 'Weekday Todo' });
    await expect(weekdayRow).toBeVisible({ timeout: 5000 });
    // The schedule text shows "Mon, Wed" in the sub-label
    await expect(weekdayRow.getByText(/Mon.*Wed/)).toBeVisible({ timeout: 3000 });

    // Clean up
    await weekdayRow.getByRole('button', { name: 'Remove' }).click();
    await page.getByRole('button', { name: 'Done' }).last().click();

    await ctx.close();
  });

  test('streak counter shows after consecutive completions', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();

    const today = new Date().toISOString().split('T')[0];
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    const dayBefore = new Date(Date.now() - 2 * 86400000).toISOString().split('T')[0];

    // Create the todo
    const todoId = psql(
      `INSERT INTO todos (user_id, name, schedule) VALUES (${user.id}, 'Streak Test Todo', '{"type":"daily"}') RETURNING id`
    );

    // Insert completions for 3 consecutive days
    psql(`
      INSERT INTO todo_completions (todo_id, user_id, completion_date) VALUES
        (${todoId}, ${user.id}, '${dayBefore}'),
        (${todoId}, ${user.id}, '${yesterday}'),
        (${todoId}, ${user.id}, '${today}')
      ON CONFLICT DO NOTHING
    `);

    await loginAndGo(page);

    // Find the todo row — streak > 1 renders as "Nd" text in a span
    const todoRow = page.locator('li').filter({ hasText: 'Streak Test Todo' });
    await todoRow.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => {});
    await expect(todoRow).toBeVisible({ timeout: 10000 });

    // The streak span shows "{streak}d" — for 3 consecutive days it should show "3d"
    await expect(todoRow.getByText('3d')).toBeVisible({ timeout: 5000 });

    // Cleanup
    psql(`DELETE FROM todos WHERE id = ${todoId}`);

    await ctx.close();
  });

  test('streak resets after missed day', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();

    const today = new Date().toISOString().split('T')[0];
    // Skip yesterday — gap means streak resets to 1
    const threeDaysAgo = new Date(Date.now() - 3 * 86400000).toISOString().split('T')[0];

    const todoId = psql(
      `INSERT INTO todos (user_id, name, schedule) VALUES (${user.id}, 'Reset Streak Todo', '{"type":"daily"}') RETURNING id`
    );

    // Completions for today and 3 days ago (yesterday is missing — streak breaks)
    psql(`
      INSERT INTO todo_completions (todo_id, user_id, completion_date) VALUES
        (${todoId}, ${user.id}, '${threeDaysAgo}'),
        (${todoId}, ${user.id}, '${today}')
      ON CONFLICT DO NOTHING
    `);

    await loginAndGo(page);

    const todoRow = page.locator('li').filter({ hasText: 'Reset Streak Todo' });
    await todoRow.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => {});
    await expect(todoRow).toBeVisible({ timeout: 10000 });

    // Streak is 1 (today only), so the "Nd" span is NOT rendered (streak > 1 is required)
    // Verify "3d" is not present (would mean streak was wrongly counted as 3)
    await expect(todoRow.getByText('3d')).not.toBeVisible({ timeout: 2000 });
    // Also confirm "2d" is absent
    await expect(todoRow.getByText('2d')).not.toBeVisible({ timeout: 2000 });

    // Cleanup
    psql(`DELETE FROM todos WHERE id = ${todoId}`);

    await ctx.close();
  });

  test('todo time of day displays in list', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    // Open manager
    const addTodoBtn = page.getByText('Add a todo');
    const hasAddBtn = await addTodoBtn.isVisible({ timeout: 2000 }).catch(() => false);

    if (hasAddBtn) {
      await addTodoBtn.click();
    } else {
      await page.getByRole('button', { name: 'Edit' }).first().click();
      await page.getByRole('button', { name: 'Add todo' }).click();
    }

    const nameInput = page.locator('input[placeholder="Todo name"]');
    await expect(nameInput).toBeVisible({ timeout: 5000 });
    await nameInput.fill('Timed Todo');

    // Pick a time using the native time picker
    const timeInput = page.getByLabel('Time of day');
    await expect(timeInput).toHaveAttribute('type', 'time');
    await timeInput.fill('08:00');

    await page.getByRole('button', { name: 'Add', exact: true }).click();

    // Close manager if Done button is visible
    const doneBtn = page.getByRole('button', { name: 'Done' });
    if (await doneBtn.isVisible({ timeout: 1000 }).catch(() => false)) {
      await doneBtn.last().click();
    }

    // The todo row in the list should show the time
    const todoRow = page.locator('li').filter({ hasText: 'Timed Todo' });
    await expect(todoRow).toBeVisible({ timeout: 5000 });
    await expect(todoRow.getByText(/08:00/)).toBeVisible({ timeout: 3000 });

    // Clean up
    await page.getByRole('button', { name: 'Edit' }).first().click();
    const timedRow = page.locator('li').filter({ hasText: 'Timed Todo' });
    await timedRow.getByRole('button', { name: 'Remove' }).click();
    await page.getByRole('button', { name: 'Done' }).last().click();

    await ctx.close();
  });

  test('Clear button empties the time picker and persists the cleared time', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    // Create a todo that has a time of day
    const addTodoBtn = page.getByText('Add a todo');
    if (await addTodoBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await addTodoBtn.click();
    } else {
      await page.getByRole('button', { name: 'Edit' }).first().click();
      await page.getByRole('button', { name: 'Add todo' }).click();
    }
    const nameInput = page.locator('input[placeholder="Todo name"]');
    await expect(nameInput).toBeVisible({ timeout: 5000 });
    await nameInput.fill('Clearable Todo');
    await page.getByLabel('Time of day').fill('09:30');
    await page.getByRole('button', { name: 'Add', exact: true }).click();

    // Reopen it for editing — the saved time should be loaded into the picker
    const managerRow = page.locator('li').filter({ hasText: 'Clearable Todo' });
    await expect(managerRow).toBeVisible({ timeout: 5000 });
    await managerRow.getByRole('button', { name: 'Edit' }).click();
    const timeInput = page.getByLabel('Time of day');
    await expect(timeInput).toHaveValue('09:30');

    // The Clear button must not be covered by anything. The icon this field
    // used to render was absolutely positioned against the wrapper that also
    // holds this button, so it landed on top of the label ("Clea🕑") and made
    // the button look broken. Assert no unrelated element overlaps its box.
    const clearBtn = page.getByRole('button', { name: 'Clear' });
    await expect(clearBtn).toBeVisible();
    const clearBox = (await clearBtn.boundingBox())!;
    const timeBox = (await timeInput.boundingBox())!;
    expect(timeBox.x + timeBox.width).toBeLessThanOrEqual(clearBox.x);

    const overlapping = await clearBtn.evaluate((btn) => {
      const target = btn.getBoundingClientRect();
      return [...document.body.querySelectorAll('*')]
        .filter((el) => el !== btn && !el.contains(btn) && !btn.contains(el))
        .filter((el) => {
          const r = el.getBoundingClientRect();
          return (
            r.width > 0 &&
            r.height > 0 &&
            r.left < target.right &&
            r.right > target.left &&
            r.top < target.bottom &&
            r.bottom > target.top
          );
        })
        .map((el) => `${el.tagName.toLowerCase()}:${(el.textContent ?? '').trim().slice(0, 12)}`);
    });
    expect(overlapping).toEqual([]);

    // Clearing empties the picker and hides the button
    await clearBtn.click();
    await expect(timeInput).toHaveValue('');
    await expect(clearBtn).toBeHidden();

    // Saving persists the cleared time (the dashboard has another Save button,
    // so scope to the row holding the open todo editor)
    const editRow = page.locator('li').filter({ has: page.getByLabel('Time of day') });
    await editRow.getByRole('button', { name: 'Save' }).click();
    await page.getByRole('button', { name: 'Done' }).last().click();

    const listRow = page.locator('li').filter({ hasText: 'Clearable Todo' });
    await expect(listRow).toBeVisible({ timeout: 5000 });
    await expect(listRow.getByText(/09:30/)).toBeHidden();
    expect(
      psql(`SELECT COALESCE(time_of_day::text, 'NULL') FROM todos WHERE user_id = :id AND name = 'Clearable Todo'`, {
        id: user.id,
      })
    ).toBe('NULL');

    // Clean up
    await page.getByRole('button', { name: 'Edit' }).first().click();
    await page.locator('li').filter({ hasText: 'Clearable Todo' }).getByRole('button', { name: 'Remove' }).click();
    await page.getByRole('button', { name: 'Done' }).last().click();

    await ctx.close();
  });
});
