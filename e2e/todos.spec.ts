import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { psql } from './fixtures/helpers';

test.describe('Todos', () => {
  test('create, complete, and delete a todo', async ({ page }) => {
    await login(page);

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
    await page.getByRole('button', { name: 'Edit' }).click();

    // Find "Remove" button for our todo in the manager
    await page.getByRole('button', { name: 'Remove' }).click();

    // Close manager
    await page.getByRole('button', { name: 'Done' }).last().click();

    // Todo should be gone
    await expect(page.getByText('E2E Test Todo')).not.toBeVisible({ timeout: 5000 });
  });

  test('edit todo name persists after reload', async ({ page }) => {
    await login(page);

    // Open the manager via the Edit button (there should be at least one todo, or create one)
    const todosSection = page.locator('div').filter({ has: page.getByText('Todos', { exact: true }) }).first();
    await todosSection.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => {});

    // If there are no todos, create one first
    const addTodoBtn = page.getByText('Add a todo');
    const editBtn = page.getByRole('button', { name: 'Edit' });
    const hasAddBtn = await addTodoBtn.isVisible({ timeout: 2000 }).catch(() => false);

    if (hasAddBtn) {
      await addTodoBtn.click();
      const nameInput = page.locator('input[placeholder="Todo name"]');
      await expect(nameInput).toBeVisible({ timeout: 5000 });
      await nameInput.fill('Todo To Edit');
      await page.getByRole('button', { name: 'Add', exact: true }).click();
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
    await page.getByRole('button', { name: 'Edit' }).click();

    const todoManagerRow = page.locator('li').filter({ hasText: 'Todo To Edit' });
    await expect(todoManagerRow).toBeVisible({ timeout: 5000 });
    await todoManagerRow.getByRole('button', { name: 'Edit' }).click();

    // The edit form should appear inline — change the name
    const editInput = todoManagerRow.locator('input[maxlength="100"]');
    await expect(editInput).toBeVisible({ timeout: 3000 });
    await editInput.fill('Renamed Todo');
    await todoManagerRow.getByRole('button', { name: 'Save' }).click();

    // Close manager
    await page.getByRole('button', { name: 'Done' }).last().click();

    // Should see the renamed todo in the list
    await expect(page.getByText('Renamed Todo')).toBeVisible({ timeout: 5000 });

    // Reload and verify persistence
    await page.reload();
    await page.waitForURL('/dashboard');
    await page.waitForLoadState('domcontentloaded');
    await expect(page.getByText('Renamed Todo')).toBeVisible({ timeout: 10000 });

    // Clean up: delete the renamed todo
    await page.getByRole('button', { name: 'Edit' }).click();
    const renamedRow = page.locator('li').filter({ hasText: 'Renamed Todo' });
    await renamedRow.getByRole('button', { name: 'Remove' }).click();
    await page.getByRole('button', { name: 'Done' }).last().click();
  });

  test('todo with specific weekdays shows schedule in manager', async ({ page }) => {
    await login(page);

    // Open manager — if no todos yet, we need the Edit button to be visible
    const addTodoBtn = page.getByText('Add a todo');
    const hasAddBtn = await addTodoBtn.isVisible({ timeout: 2000 }).catch(() => false);

    if (hasAddBtn) {
      await addTodoBtn.click();
    } else {
      await page.getByRole('button', { name: 'Edit' }).click();
      await page.getByRole('button', { name: 'Add todo' }).click();
    }

    // Fill the name
    const nameInput = page.locator('input[placeholder="Todo name"]');
    await expect(nameInput).toBeVisible({ timeout: 5000 });
    await nameInput.fill('Weekday Todo');

    // Switch to "Specific days" schedule
    const specificDaysRadio = page.getByLabel('Specific days');
    await specificDaysRadio.click();

    // Select only Mon and Wed (days 1 and 3)
    await page.getByRole('button', { name: 'Mon' }).click();
    // By default Mon–Fri are selected after switching; deselect Tue, Thu, Fri
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
    await page.getByRole('button', { name: 'Edit' }).click();
    const weekdayRow = page.locator('li').filter({ hasText: 'Weekday Todo' });
    await expect(weekdayRow).toBeVisible({ timeout: 5000 });
    // The schedule text shows "Mon, Wed" in the sub-label
    await expect(weekdayRow.getByText(/Mon.*Wed/)).toBeVisible({ timeout: 3000 });

    // Clean up
    await weekdayRow.getByRole('button', { name: 'Remove' }).click();
    await page.getByRole('button', { name: 'Done' }).last().click();
  });

  test('streak counter shows after consecutive completions', async ({ page }) => {
    // Insert a todo and completions for today, yesterday, and day-before via psql
    const userId = psql(`SELECT id FROM users WHERE email = 'test@test.com'`);
    const today = new Date().toISOString().split('T')[0];
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    const dayBefore = new Date(Date.now() - 2 * 86400000).toISOString().split('T')[0];

    // Create the todo
    const todoId = psql(
      `INSERT INTO todos (user_id, name, schedule) VALUES (${userId}, 'Streak Test Todo', '{"type":"daily"}') RETURNING id`
    );

    // Insert completions for 3 consecutive days
    psql(`
      INSERT INTO todo_completions (todo_id, user_id, completion_date) VALUES
        (${todoId}, ${userId}, '${dayBefore}'),
        (${todoId}, ${userId}, '${yesterday}'),
        (${todoId}, ${userId}, '${today}')
      ON CONFLICT DO NOTHING
    `);

    await login(page);

    // Navigate to dashboard (viewing today)
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    // Find the todo row — streak > 1 renders as "Nd" text in a span
    const todoRow = page.locator('li').filter({ hasText: 'Streak Test Todo' });
    await todoRow.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => {});
    await expect(todoRow).toBeVisible({ timeout: 10000 });

    // The streak span shows "{streak}d" — for 3 consecutive days it should show "3d"
    await expect(todoRow.getByText('3d')).toBeVisible({ timeout: 5000 });

    // Cleanup
    psql(`DELETE FROM todos WHERE id = ${todoId}`);
  });

  test('streak resets after missed day', async ({ page }) => {
    const userId = psql(`SELECT id FROM users WHERE email = 'test@test.com'`);
    const today = new Date().toISOString().split('T')[0];
    // Skip yesterday — gap means streak resets to 1
    const threeDaysAgo = new Date(Date.now() - 3 * 86400000).toISOString().split('T')[0];

    const todoId = psql(
      `INSERT INTO todos (user_id, name, schedule) VALUES (${userId}, 'Reset Streak Todo', '{"type":"daily"}') RETURNING id`
    );

    // Completions for today and 3 days ago (yesterday is missing — streak breaks)
    psql(`
      INSERT INTO todo_completions (todo_id, user_id, completion_date) VALUES
        (${todoId}, ${userId}, '${threeDaysAgo}'),
        (${todoId}, ${userId}, '${today}')
      ON CONFLICT DO NOTHING
    `);

    await login(page);
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

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
  });

  test('todo time of day displays in list', async ({ page }) => {
    await login(page);

    // Open manager
    const addTodoBtn = page.getByText('Add a todo');
    const hasAddBtn = await addTodoBtn.isVisible({ timeout: 2000 }).catch(() => false);

    if (hasAddBtn) {
      await addTodoBtn.click();
    } else {
      await page.getByRole('button', { name: 'Edit' }).click();
      await page.getByRole('button', { name: 'Add todo' }).click();
    }

    const nameInput = page.locator('input[placeholder="Todo name"]');
    await expect(nameInput).toBeVisible({ timeout: 5000 });
    await nameInput.fill('Timed Todo');

    // Enter a time using the HH:MM input
    const timeInput = page.locator('input[placeholder="HH:MM"]');
    await timeInput.fill('0800');
    await timeInput.blur(); // triggers formatting

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
    await page.getByRole('button', { name: 'Edit' }).click();
    const timedRow = page.locator('li').filter({ hasText: 'Timed Todo' });
    await timedRow.getByRole('button', { name: 'Remove' }).click();
    await page.getByRole('button', { name: 'Done' }).last().click();
  });
});
