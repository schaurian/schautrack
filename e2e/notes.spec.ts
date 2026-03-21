import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

/** Find the Daily Notes settings card and its toggle button. */
async function getNotesToggle(page: import('@playwright/test').Page) {
  // The h3 "Daily Notes" is inside a Card. Go up to the card, then find the toggle sibling.
  const heading = page.getByRole('heading', { name: 'Daily Notes' });
  // The toggle is a sibling button in the same flex row
  const card = heading.locator('..');  // parent div (the flex row)
  const toggle = card.locator('button').first();
  return { heading, toggle };
}

test.describe('Daily Notes', () => {
  test.beforeEach(async ({ page }) => {
    await login(page);
  });

  test('enable notes and write a note', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForURL('/settings');

    const { heading, toggle } = await getNotesToggle(page);
    await heading.scrollIntoViewIfNeeded();

    // Ensure notes are enabled
    const description = page.getByText('Write a daily note');
    const isEnabled = await description.isVisible({ timeout: 2000 }).catch(() => false);
    if (!isEnabled) {
      await toggle.click();
      await page.waitForTimeout(500);
      await expect(description).toBeVisible();
    }

    // Go to dashboard
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    // Notes section should be visible
    const textarea = page.locator('textarea[placeholder*="Write a note"]');
    await expect(textarea).toBeVisible({ timeout: 5000 });

    // Write a note
    const testNote = `E2E test note ${Date.now()}`;
    await textarea.fill(testNote);

    // Wait for autosave (1s debounce + network round-trip)
    // "Saving..." is too transient to reliably catch, just wait for "Saved"
    await expect(page.getByText('Saved')).toBeVisible({ timeout: 5000 });

    // Reload and verify persistence
    await page.reload();
    await page.waitForURL('/dashboard');
    await page.waitForLoadState('domcontentloaded');
    const reloadedTextarea = page.locator('textarea[placeholder*="Write a note"]');
    await expect(reloadedTextarea).toHaveValue(testNote, { timeout: 10000 });

    // Clear the note
    await reloadedTextarea.fill('');
    await expect(page.getByText('Saved')).toBeVisible({ timeout: 5000 });
  });

  test('notes are date-specific', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    const textarea = page.locator('textarea[placeholder*="Write a note"]');
    await textarea.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => {});
    const hasNotes = await textarea.isVisible({ timeout: 5000 }).catch(() => false);
    if (!hasNotes) {
      test.skip(true, 'Notes not enabled for test user');
      return;
    }

    // Write note for today
    const todayNote = `Today note ${Date.now()}`;
    await textarea.fill(todayNote);
    await expect(page.getByText('Saved')).toBeVisible({ timeout: 5000 });

    // Click a different date dot (yesterday-ish — pick the second-to-last dot)
    const dots = page.locator('button[title]').filter({ has: page.locator('[class*="rounded"]') });
    const dotCount = await dots.count();
    if (dotCount > 1) {
      await dots.nth(dotCount - 2).click();
      await page.waitForTimeout(500);

      // Note should be empty for the other date
      const otherTextarea = page.locator('textarea[placeholder*="Write a note"]');
      await expect(otherTextarea).toHaveValue('', { timeout: 3000 });
    }
  });

  test('disable notes hides editor', async ({ page }) => {
    await page.goto('/settings');
    await page.waitForURL('/settings');

    const { heading, toggle } = await getNotesToggle(page);
    await heading.scrollIntoViewIfNeeded();

    // Ensure notes are enabled first
    const description = page.getByText('Write a daily note');
    const isEnabled = await description.isVisible({ timeout: 2000 }).catch(() => false);
    if (!isEnabled) {
      await toggle.click();
      await page.waitForTimeout(500);
    }

    // Disable notes
    await toggle.click();
    await page.waitForTimeout(500);

    // Go to dashboard — note editor should not be visible
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');
    const textarea = page.locator('textarea[placeholder*="Write a note"]');
    await expect(textarea).not.toBeVisible({ timeout: 3000 });

    // Re-enable notes for other tests
    await page.goto('/settings');
    await page.waitForURL('/settings');
    const { heading: h2, toggle: t2 } = await getNotesToggle(page);
    await h2.scrollIntoViewIfNeeded();
    await t2.click();
    await page.waitForTimeout(500);
  });

  test('character limit is enforced', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    const textarea = page.locator('textarea[placeholder*="Write a note"]');
    await textarea.scrollIntoViewIfNeeded({ timeout: 5000 }).catch(() => {});
    const hasNotes = await textarea.isVisible({ timeout: 5000 }).catch(() => false);
    if (!hasNotes) {
      test.skip(true, 'Notes not enabled for test user');
      return;
    }

    // Check maxLength attribute
    await expect(textarea).toHaveAttribute('maxLength', '10000');

    // Verify counter is visible
    await expect(page.getByText('/10000')).toBeVisible();

    // Clean up
    await textarea.fill('');
    await page.waitForTimeout(1500);
  });
});
