import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };
let targetUser: { email: string; password: string; id: string };

test.describe('Security', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    user = createIsolatedUser('security');
    targetUser = createIsolatedUser('security-target');
    // Ensure no link exists between them
    psql(`DELETE FROM account_links WHERE
      (requester_id = ${user.id} AND target_id = ${targetUser.id}) OR
      (requester_id = ${targetUser.id} AND target_id = ${user.id})`);
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
      await page.waitForURL(new RegExp(path.replace('/', '\\/')), { timeout: 10000 });
    }
  }

  test('cannot access another user\'s entry via API', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    // Insert an entry belonging to the target user directly in DB
    const today = new Date().toISOString().split('T')[0];
    psql(`INSERT INTO calorie_entries (user_id, entry_name, amount, entry_date) VALUES (${targetUser.id}, 'security-test-entry', 999, '${today}')`);
    const entryId = psql(`SELECT id FROM calorie_entries WHERE user_id = ${targetUser.id} AND entry_name = 'security-test-entry' ORDER BY id DESC LIMIT 1`);
    expect(entryId).toBeTruthy();

    const csrfRes = await page.request.get(`${baseURL}/api/csrf`);
    const { token } = await csrfRes.json();

    // As main user, try to delete target user's entry
    const response = await page.request.post(`${baseURL}/entries/${entryId}/delete`, {
      headers: { 'X-CSRF-Token': token },
    });

    // The API returns 200 even if no row was deleted (WHERE user_id filter prevents cross-user delete)
    expect([200, 403, 404]).toContain(response.status());

    // Verify the entry still exists in DB
    const stillExists = psql(`SELECT id FROM calorie_entries WHERE id = ${entryId} AND user_id = ${targetUser.id}`);
    expect(stillExists).toBeTruthy();

    // Cleanup
    psql(`DELETE FROM calorie_entries WHERE id = ${entryId}`);
    await ctx.close();
  });

  test('cannot access linked user data without active link', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    // Confirm no active link exists (already cleared in beforeAll)
    const today = new Date().toISOString().split('T')[0];
    const response = await page.request.get(`${baseURL}/entries/day?user=${targetUser.id}&date=${today}`);

    expect([403, 404]).toContain(response.status());
    await ctx.close();
  });

  test('session cookie is httpOnly', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const cookies = await ctx.cookies();
    const sessionCookie = cookies.find((c) => c.name === 'schautrack.sid');

    expect(sessionCookie).toBeDefined();
    expect(sessionCookie!.httpOnly).toBe(true);
    await ctx.close();
  });

  test('session cookie has sameSite lax or strict', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const cookies = await ctx.cookies();
    const sessionCookie = cookies.find((c) => c.name === 'schautrack.sid');

    expect(sessionCookie).toBeDefined();
    expect(['Lax', 'Strict']).toContain(sessionCookie!.sameSite);
    await ctx.close();
  });

  test('failed login returns 401 not 429 under normal conditions', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const freshPage = await ctx.newPage();

    await freshPage.goto(`${baseURL}/login`);
    await freshPage.waitForLoadState('domcontentloaded');

    const csrfRes = await freshPage.request.get(`${baseURL}/api/csrf`);
    const { token } = await csrfRes.json();

    const response = await freshPage.request.post(`${baseURL}/api/auth/login`, {
      data: { email: 'nobody@example.com', password: 'wrongpassword' },
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
      },
    });

    expect(response.status()).toBe(401);
    expect(response.status()).not.toBe(429);

    await ctx.close();
  });

  test('unauthenticated API requests return 401', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const freshPage = await ctx.newPage();

    const response = await freshPage.request.get(`${baseURL}/api/me`);
    expect(response.status()).toBe(401);

    await ctx.close();
  });

  test('cannot access admin routes as non-admin user', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginAndGo(page);

    const response = await page.request.get(`${baseURL}/admin/invites`);
    expect(response.status()).toBe(403);
    await ctx.close();
  });

  test('API returns 401 for protected endpoints without session', async ({ browser }) => {
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const freshPage = await ctx.newPage();

    const dashResponse = await freshPage.request.get(`${baseURL}/api/dashboard`);
    expect(dashResponse.status()).toBe(401);

    await ctx.close();
  });
});
