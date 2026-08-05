import { test, expect, type Page } from '@playwright/test';
import { psql, createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';

let user: { email: string; password: string; id: string };

/**
 * The welcome tour: opens by itself on the first login, closes for good, and
 * can be replayed from Settings.
 *
 * Runs on its own user with a fresh context every time. The shared session's
 * account is deliberately left alone — setup-test-user.ts marks every seeded
 * account as onboarded, and flipping that back for test@test.com would drop a
 * modal over every spec running in parallel.
 */
test.describe('Welcome tour', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('onboarding');
  });

  /** Put the account back in its never-seen-the-tour state. */
  function resetTour() {
    psql(`UPDATE users SET onboarding_completed_at = NULL WHERE id = ${user.id}`);
  }

  function completedAt(): string {
    return psql(`SELECT onboarding_completed_at FROM users WHERE id = ${user.id}`);
  }

  async function login(page: Page) {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
  }

  test('opens by itself on the first login and closes for good', async ({ browser }) => {
    resetTour();
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);

    const tour = page.getByTestId('welcome-tour');
    await expect(tour).toBeVisible({ timeout: 10000 });
    await expect(tour.getByText('One day at a time')).toBeVisible();
    await expect(tour.getByText('1 of 5')).toBeVisible();

    await page.getByTestId('welcome-tour-close').click();
    await expect(tour).toHaveCount(0);

    // Dismissal is persisted, so a reload must not bring it back.
    await page.reload();
    await page.waitForURL(/\/dashboard/);
    await expect(page.getByTestId('welcome-tour')).toHaveCount(0, { timeout: 5000 });
    expect(completedAt()).not.toBe('');

    await ctx.close();
  });

  test('steps forward and back through all five steps', async ({ browser }) => {
    resetTour();
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);

    const tour = page.getByTestId('welcome-tour');
    await expect(tour).toBeVisible({ timeout: 10000 });

    for (let step = 2; step <= 5; step++) {
      await page.getByTestId('welcome-tour-next').click();
      await expect(tour.getByText(`${step} of 5`)).toBeVisible();
    }
    // Last step swaps Next for the closing action.
    await expect(page.getByTestId('welcome-tour-next')).toHaveText('Start tracking');

    await tour.getByRole('button', { name: 'Back' }).click();
    await expect(tour.getByText('4 of 5')).toBeVisible();

    // Finishing counts as dismissing.
    await page.getByTestId('welcome-tour-next').click();
    await page.getByTestId('welcome-tour-next').click();
    await expect(tour).toHaveCount(0);
    expect(completedAt()).not.toBe('');

    await ctx.close();
  });

  test('Escape closes it', async ({ browser }) => {
    resetTour();
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);

    const tour = page.getByTestId('welcome-tour');
    await expect(tour).toBeVisible({ timeout: 10000 });
    await page.keyboard.press('Escape');
    await expect(tour).toHaveCount(0);

    await ctx.close();
  });

  test('Settings replays it for an account that already dismissed it', async ({ browser }) => {
    // Already onboarded: the tour must stay shut until it is asked for.
    psql(`UPDATE users SET onboarding_completed_at = NOW() WHERE id = ${user.id}`);
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await login(page);
    await expect(page.getByTestId('welcome-tour')).toHaveCount(0, { timeout: 5000 });

    await page.goto(`${baseURL}/settings`);
    await expect(page.getByTestId('settings-page')).toBeVisible({ timeout: 10000 });
    await page.getByTestId('replay-tour').click();

    const tour = page.getByTestId('welcome-tour');
    await expect(tour).toBeVisible({ timeout: 5000 });
    // Replays start at the beginning.
    await expect(tour.getByText('1 of 5')).toBeVisible();
    await page.getByTestId('welcome-tour-close').click();
    await expect(tour).toHaveCount(0);

    await ctx.close();
  });
});
