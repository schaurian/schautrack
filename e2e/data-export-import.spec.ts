import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe('Data Export / Import', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('data-export');
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

  test('export data as JSON', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();

    // Seed test data via psql
    psql(`INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name) VALUES (${user.id}, '2026-01-15', 350, 'E2E Export Meal') ON CONFLICT DO NOTHING`);
    psql(`INSERT INTO weight_entries (user_id, entry_date, weight) VALUES (${user.id}, '2026-01-15', 72.5) ON CONFLICT (user_id, entry_date) DO UPDATE SET weight = 72.5`);

    await loginAndGo(page, '/settings');

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

    await ctx.close();
  });

  test('import data from JSON', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();

    // Build a JSON fixture matching the export format
    const importFixture = {
      exported_at: new Date().toISOString(),
      user: {
        email: user.email,
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

    await loginAndGo(page, '/settings');

    // Scroll to and click the file chooser button (hidden input via button proxy)
    const fileChooserButton = page.locator('button', { hasText: 'Choose a file' });
    await fileChooserButton.scrollIntoViewIfNeeded({ timeout: 10000 });

    // Use setInputFiles on the hidden file input
    const fileInput = page.locator('input[type="file"][accept=".json,application/json"]');
    await fileInput.setInputFiles(tmpFile);

    // Import button should now be enabled
    const importBtn = page.getByRole('button', { name: 'Import', exact: true });
    await expect(importBtn).toBeEnabled({ timeout: 5000 });

    // Click Import and wait for success message
    await importBtn.click();
    await expect(page.getByText(/Imported/i)).toBeVisible({ timeout: 15000 });

    // Clean up temp file
    fs.unlinkSync(tmpFile);

    // Verify imported entries are in the DB
    const importedCount = psql(
      `SELECT COUNT(*) FROM calorie_entries WHERE user_id = ${user.id} AND entry_date = '2026-03-10' AND entry_name LIKE 'E2E Import%'`
    );
    expect(Number(importedCount)).toBe(2);

    const importedWeight = psql(
      `SELECT weight FROM weight_entries WHERE user_id = ${user.id} AND entry_date = '2026-03-10'`
    );
    expect(parseFloat(importedWeight)).toBeCloseTo(68.0);

    await ctx.close();
  });

  test('Import button is disabled until file is selected', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();

    await loginAndGo(page, '/settings');

    const importBtn = page.getByRole('button', { name: 'Import', exact: true });
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
        user: { email: user.email, daily_goal: 2000 },
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

    await ctx.close();
  });
});
