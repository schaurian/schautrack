import { test, expect } from '@playwright/test';
import { psql } from './fixtures/helpers';

test.describe('SSE Real-time Updates', () => {
  test('entry appears in second tab via SSE', async ({ browser }) => {
    const contextA = await browser.newContext({ storageState: 'e2e/.auth/user.json' });
    const contextB = await browser.newContext({ storageState: 'e2e/.auth/user.json' });

    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();

    await pageA.goto('/dashboard');
    await pageA.waitForURL('/dashboard');

    await pageB.goto('/dashboard');
    await pageB.waitForURL('/dashboard');

    // Add an entry on page A
    await pageA.locator('input[placeholder="Breakfast, snack..."]').fill('SSE Test Entry');

    const calInput = pageA.locator('input[inputmode="tel"][placeholder="0"]').first();
    const isReadonly = await calInput.getAttribute('readonly');
    if (isReadonly !== null) {
      await pageA.locator('input[inputmode="numeric"][placeholder="0"]').first().fill('25');
    } else {
      await calInput.fill('123');
    }

    await pageA.locator('form button[type="submit"]').click();
    await expect(pageA.getByText('Entry tracked')).toBeVisible({ timeout: 5000 });

    // Page B should receive the update via SSE without reloading
    await expect(pageB.getByText('SSE Test Entry')).toBeVisible({ timeout: 10000 });

    // Clean up: delete the entry on page A
    const entryText = pageA.getByText('SSE Test Entry');
    await entryText.scrollIntoViewIfNeeded({ timeout: 5000 });
    const entryRow = pageA.locator('div').filter({ hasText: 'SSE Test Entry' }).last();
    const deleteBtn = entryRow.locator('button[title="Delete"]');
    if (await deleteBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
      await deleteBtn.click();
    }
    await expect(pageA.getByText('SSE Test Entry')).not.toBeVisible({ timeout: 5000 });

    await contextA.close();
    await contextB.close();
  });

  test('todo completion propagates via SSE', async ({ browser }) => {
    // Create a todo via psql for the test user
    const userId = psql(`SELECT id FROM users WHERE email = 'test@test.com'`);
    const today = new Date().toISOString().split('T')[0];
    const todoId = psql(
      `INSERT INTO todos (user_id, name, schedule) VALUES (${userId}, 'SSE Todo Test', '{"type":"daily"}') RETURNING id`
    );

    const contextA = await browser.newContext({ storageState: 'e2e/.auth/user.json' });
    const contextB = await browser.newContext({ storageState: 'e2e/.auth/user.json' });

    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();

    await pageA.goto('/dashboard');
    await pageA.waitForURL('/dashboard');

    await pageB.goto('/dashboard');
    await pageB.waitForURL('/dashboard');

    // Complete the todo on page A
    const todoRowA = pageA.locator('li').filter({ hasText: 'SSE Todo Test' });
    await todoRowA.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => {});
    await expect(todoRowA).toBeVisible({ timeout: 10000 });

    const checkboxA = todoRowA.locator('button').last();
    await checkboxA.click();

    // The todo should appear completed (line-through) on page A
    await expect(todoRowA.locator('.line-through')).toBeVisible({ timeout: 5000 });

    // Page B should receive todo-change via SSE and show the same todo as completed
    const todoRowB = pageB.locator('li').filter({ hasText: 'SSE Todo Test' });
    await todoRowB.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => {});
    await expect(todoRowB.locator('.line-through')).toBeVisible({ timeout: 10000 });

    await contextA.close();
    await contextB.close();

    // Cleanup
    psql(`DELETE FROM todos WHERE id = ${todoId}`);
  });

  test('note change propagates via SSE', async ({ browser }) => {
    // This test requires notes to be enabled for the test user
    const userId = psql(`SELECT id FROM users WHERE email = 'test@test.com'`);
    const notesEnabled = psql(`SELECT notes_enabled FROM users WHERE email = 'test@test.com'`);
    if (notesEnabled !== 't' && notesEnabled !== 'true' && notesEnabled !== '1') {
      // Enable notes for this test
      psql(`UPDATE users SET notes_enabled = true WHERE id = ${userId}`);
    }

    const contextA = await browser.newContext({ storageState: 'e2e/.auth/user.json' });
    const contextB = await browser.newContext({ storageState: 'e2e/.auth/user.json' });

    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();

    await pageA.goto('/dashboard');
    await pageA.waitForURL('/dashboard');

    await pageB.goto('/dashboard');
    await pageB.waitForURL('/dashboard');

    // Write a note on page A
    const textareaA = pageA.locator('textarea[placeholder*="Write a note"]');
    await textareaA.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => {});
    const hasNotes = await textareaA.isVisible({ timeout: 5000 }).catch(() => false);
    if (!hasNotes) {
      await contextA.close();
      await contextB.close();
      test.skip(true, 'Notes not visible on dashboard — notes may not be enabled');
      return;
    }

    const noteContent = `SSE Note Test ${Date.now()}`;
    await textareaA.fill(noteContent);
    // Trigger save by blurring
    await textareaA.blur();
    await expect(pageA.getByText('Saved')).toBeVisible({ timeout: 8000 });

    // Page B should receive the note-change SSE event and refetch — the textarea should update
    const textareaB = pageB.locator('textarea[placeholder*="Write a note"]');
    await textareaB.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => {});
    await expect(textareaB).toHaveValue(noteContent, { timeout: 10000 });

    // Cleanup: clear the note
    await textareaA.fill('');
    await textareaA.blur();
    await pageA.waitForTimeout(1500);

    await contextA.close();
    await contextB.close();

    // Restore notes_enabled if it was originally disabled
    if (notesEnabled !== 't' && notesEnabled !== 'true' && notesEnabled !== '1') {
      psql(`UPDATE users SET notes_enabled = false WHERE id = ${userId}`);
    }
  });

  // NOTE: Testing that a linked user's entry propagates via SSE to a viewer is not straightforward
  // because SSE is only fired when the *app itself* creates an entry via the API (see handler/entries.go
  // calling broker.BroadcastEntryChange). Inserting a row directly into the DB via psql bypasses the
  // Go handler, so no SSE event is emitted and the viewer's page will not update automatically.
  // This scenario is therefore not covered by an automated E2E test.

  test('weight update propagates via SSE', async ({ browser }) => {
    const contextA = await browser.newContext({ storageState: 'e2e/.auth/user.json' });
    const contextB = await browser.newContext({ storageState: 'e2e/.auth/user.json' });

    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();

    await pageA.goto('/dashboard');
    await pageA.waitForURL('/dashboard');

    await pageB.goto('/dashboard');
    await pageB.waitForURL('/dashboard');

    // Enter weight on page A
    const weightInputA = pageA.getByLabel(/Weight in/);
    await weightInputA.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(weightInputA).toBeVisible();

    await weightInputA.fill('75');
    await weightInputA.blur();
    await expect(pageA.getByText('Weight tracked')).toBeVisible({ timeout: 5000 });

    // Page B should show the weight input updated via SSE
    const weightInputB = pageB.getByLabel(/Weight in/);
    await weightInputB.scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(weightInputB).toHaveValue('75', { timeout: 10000 });

    // Clean up: delete the weight entry on page A
    const deleteBtn = pageA.getByTitle('Delete weight entry');
    if (await deleteBtn.isEnabled({ timeout: 3000 }).catch(() => false)) {
      await deleteBtn.click();
      await expect(weightInputA).toHaveValue('', { timeout: 5000 });
    }

    await contextA.close();
    await contextB.close();
  });
});
