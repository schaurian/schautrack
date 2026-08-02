import { test, expect } from '@playwright/test';
import { createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

// A tab that loaded index.html before a deploy asks for chunk filenames the new
// build no longer has. Rather than dropping the user on the error boundary, the
// app reloads once (lib/lazyRoute.ts) and comes back on the current build.
test.describe('Stale chunk recovery', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('stale-chunk');
  });

  test('a route whose chunk 404s reloads itself instead of erroring', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();

    // Make the chunk missing for the whole first document load — index.html
    // both modulepreloads it and imports it, so failing a single request only
    // kills the preload and proves nothing. It becomes available again once the
    // page reloads, which is exactly what a deploy looks like to an open tab.
    let navigations = 0;
    page.on('request', (r) => {
      if (r.isNavigationRequest() && r.url().includes('/settings')) navigations++;
    });

    let blocked = 0;
    await page.route(/\/assets\/Settings-.*\.js$/, async (route) => {
      if (navigations <= 1) {
        blocked++;
        await route.fulfill({ status: 404, contentType: 'text/plain', body: 'gone' });
        return;
      }
      await route.continue();
    });

    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(user.email);
    await page.getByLabel('Password').fill(user.password);
    await page.getByRole('button', { name: 'Log In', exact: true }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });

    await page.goto(`${baseURL}/settings`);

    // The chunk was missing, the page reloaded itself, and Settings rendered.
    await expect(page.getByText('Nutrition Goals')).toBeVisible({ timeout: 20000 });
    expect(blocked).toBeGreaterThan(0);
    expect(navigations).toBeGreaterThan(1);

    // And the user never saw the error boundary.
    await expect(page.getByText(/something went wrong/i)).toBeHidden();

    await ctx.close();
  });
});
