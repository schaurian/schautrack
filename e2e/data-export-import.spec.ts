import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { psql } from './fixtures/helpers';

const TEST_USER_EMAIL = 'test@test.com';

function getTestUserId(): string {
  return psql(`SELECT id FROM users WHERE email = '${TEST_USER_EMAIL}'`);
}

function cleanupTestData(userId: string) {
  psql(`DELETE FROM calorie_entries WHERE user_id = ${userId} AND entry_name LIKE 'E2E Export%'`);
  psql(`DELETE FROM weight_entries WHERE user_id = ${userId} AND entry_date = '2026-01-15'`);
}

function cleanupImportedData(userId: string) {
  psql(`DELETE FROM calorie_entries WHERE user_id = ${userId} AND entry_name LIKE 'E2E Import%'`);
  psql(`DELETE FROM weight_entries WHERE user_id = ${userId} AND entry_date = '2026-03-10'`);
}

test.describe('Data Export / Import', () => {
  test.use({ storageState: 'e2e/.auth/user.json' });

  test.afterEach(async () => {
    const userId = getTestUserId();
    if (userId) {
      cleanupTestData(userId);
      cleanupImportedData(userId);
    }
  });

  test('export data as JSON', async ({ page }) => {
    const userId = getTestUserId();

    // Seed test data via psql
    psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name) VALUES (${userId}, '2026-01-15', 350, 'E2E Export Meal') ON CONFLICT DO NOTHING`);
    psql(`INSERT INTO weight_entries (user_id, entry_date, weight) VALUES (${userId}, '2026-01-15', 72.5) ON CONFLICT (user_id, entry_date) DO UPDATE SET weight = 72.5`);

    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Locate the Export button inside the Data card
    const exportLink = page.locator('a[href="/settings/export"]');
    await exportLink.scrollIntoViewIfNeeded({ timeout: 10000 });
    await expect(exportLink).toBeVisible({ timeout: 10000 });

    // Set up download listener before clicking
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      exportLink.click(),
    ]);

    // Verify download fires and filename contains "schautrack"
    expect(download.suggestedFilename()).toContain('schautrack');

    // Read and parse the downloaded JSON
    const downloadPath = await download.path();
    expect(downloadPath).not.toBeNull();

    const content = fs.readFileSync(downloadPath!, 'utf-8');
    const data = JSON.parse(content);

    // Verify top-level structure
    expect(Array.isArray(data.entries)).toBe(true);
    expect(Array.isArray(data.weights)).toBe(true);
    expect(data.user).toBeDefined();

    // Verify our seeded entry is present
    const exportedEntry = data.entries.find(
      (e: { date: string; name?: string; amount: number }) =>
        e.date === '2026-01-15' && e.name === 'E2E Export Meal'
    );
    expect(exportedEntry).toBeDefined();
    expect(exportedEntry.amount).toBe(350);

    // Verify our seeded weight is present
    const exportedWeight = data.weights.find(
      (w: { date: string; weight: number }) => w.date === '2026-01-15'
    );
    expect(exportedWeight).toBeDefined();
    expect(exportedWeight.weight).toBeCloseTo(72.5);
  });

  test.skip('import data from JSON', async ({ page }) => {
    await login(page);

    // Build a JSON fixture matching the export format
    const importFixture = {
      exported_at: new Date().toISOString(),
      user: {
        email: TEST_USER_EMAIL,
        daily_goal: 2000,
        macros_enabled: {},
        macro_goals: {},
        weight_unit: 'kg',
        timezone: 'UTC',
      },
      entries: [
        {
          date: '2026-03-10',
          amount: 450,
          name: 'E2E Import Breakfast',
          created_at: '2026-03-10T08:00:00Z',
        },
        {
          date: '2026-03-10',
          amount: 600,
          name: 'E2E Import Lunch',
          created_at: '2026-03-10T12:00:00Z',
        },
      ],
      weights: [
        {
          date: '2026-03-10',
          weight: 68.0,
        },
      ],
    };

    // Write fixture to a temp file
    const tmpDir = os.tmpdir();
    const tmpFile = path.join(tmpDir, `schautrack-import-test-${Date.now()}.json`);
    fs.writeFileSync(tmpFile, JSON.stringify(importFixture));

    await page.goto('/settings');
    await page.waitForURL('/settings');

    // Scroll to and click the file chooser button (hidden input via button proxy)
    const fileChooserButton = page.locator('button', { hasText: 'Choose a file' });
    await fileChooserButton.scrollIntoViewIfNeeded({ timeout: 10000 });

    // Use setInputFiles on the hidden file input
    const fileInput = page.locator('input[type="file"][accept=".json,application/json"]');
    await fileInput.setInputFiles(tmpFile);

    // Import button should now be enabled
    const importBtn = page.getByRole('button', { name: 'Import' });
    await expect(importBtn).toBeEnabled({ timeout: 5000 });

    // Click Import and wait for success message
    await importBtn.click();
    await expect(page.getByText(/Imported/i)).toBeVisible({ timeout: 15000 });

    // Clean up temp file
    fs.unlinkSync(tmpFile);

    // Navigate to dashboard and verify imported entries appear
    await page.goto('/dashboard');
    await page.waitForURL('/dashboard');

    // The dashboard shows today's entries by default; navigate to the imported date
    // by checking if entries from 2026-03-10 are in the DB (they were imported)
    const userId = getTestUserId();
    const importedCount = psql(
      `SELECT COUNT(*) FROM calorie_entries WHERE user_id = ${userId} AND entry_date = '2026-03-10' AND entry_name LIKE 'E2E Import%'`
    );
    expect(Number(importedCount)).toBe(2);

    const importedWeight = psql(
      `SELECT weight FROM weight_entries WHERE user_id = ${userId} AND entry_date = '2026-03-10'`
    );
    expect(parseFloat(importedWeight)).toBeCloseTo(68.0);
  });

  test.skip('Import button is disabled until file is selected', async ({ page }) => {
    await login(page);
    await page.goto('/settings');
    await page.waitForURL('/settings');

    const importBtn = page.getByRole('button', { name: 'Import' });
    await importBtn.scrollIntoViewIfNeeded({ timeout: 10000 });

    // Button should be disabled before any file is chosen
    await expect(importBtn).toBeDisabled({ timeout: 5000 });

    // Write a minimal valid JSON to a temp file
    const tmpDir = os.tmpdir();
    const tmpFile = path.join(tmpDir, `schautrack-import-enable-test-${Date.now()}.json`);
    fs.writeFileSync(
      tmpFile,
      JSON.stringify({
        exported_at: new Date().toISOString(),
        user: { email: TEST_USER_EMAIL, daily_goal: 2000 },
        entries: [{ date: '2026-02-01', amount: 100, name: 'E2E Import Enable Test' }],
        weights: [],
      })
    );

    // Select the file
    const fileInput = page.locator('input[type="file"][accept=".json,application/json"]');
    await fileInput.setInputFiles(tmpFile);

    // Button should now be enabled
    await expect(importBtn).toBeEnabled({ timeout: 5000 });

    fs.unlinkSync(tmpFile);

    // Clean up imported entry
    const userId = getTestUserId();
    if (userId) {
      psql(`DELETE FROM calorie_entries WHERE user_id = ${userId} AND entry_name = 'E2E Import Enable Test'`);
    }
  });
});
