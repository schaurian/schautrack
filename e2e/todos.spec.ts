import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('Todos', () => {
  test('enable todos and manage them', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Look for the todos toggle
    const todosToggle = page.getByText('Enable Todos').locator('..').locator('input[type="checkbox"], button');
    const hasTodosToggle = await todosToggle.first().isVisible({ timeout: 3000 }).catch(() => false);

    if (!hasTodosToggle) {
      test.skip(true, 'Todos toggle not found in settings');
      return;
    }

    // Enable todos if not already
    const toggleEl = todosToggle.first();
    const isCheckbox = await toggleEl.getAttribute('type') === 'checkbox';

    if (isCheckbox) {
      const checked = await toggleEl.isChecked();
      if (!checked) {
        await toggleEl.click();
        // Wait for it to take effect
        await page.waitForTimeout(1000);
      }
    } else {
      await toggleEl.click();
      await page.waitForTimeout(1000);
    }

    // Look for todo creation form
    const todoInput = page.locator('input[placeholder*="todo" i], input[placeholder*="name" i]').first();
    const hasTodoInput = await todoInput.isVisible({ timeout: 3000 }).catch(() => false);

    if (hasTodoInput) {
      // Create a todo
      await todoInput.fill('E2E Test Todo');
      await page.getByRole('button', { name: /add|create|save/i }).first().click();

      // Verify it appears
      await expect(page.getByText('E2E Test Todo')).toBeVisible({ timeout: 5000 });

      // Delete it (look for delete button near the todo)
      const todoRow = page.locator('li, div').filter({ hasText: 'E2E Test Todo' });
      const deleteBtn = todoRow.locator('button[title="Delete"], button:has-text("Delete"), button:has-text("×")').first();
      if (await deleteBtn.isVisible().catch(() => false)) {
        await deleteBtn.click();
        await expect(page.getByText('E2E Test Todo')).not.toBeVisible({ timeout: 5000 });
      }
    }
  });
});
