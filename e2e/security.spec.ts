import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';
import { psql, bcryptHash } from './fixtures/helpers';

const LINK_USER_EMAIL = 'link-test@test.com';
const TEST_USER_EMAIL = 'test@test.com';

test.describe('Security', () => {
  test.skip('cannot access another user\'s entry via API', async ({ page }) => {
    await login(page);

    // Ensure link-test user exists in DB
    const linkUserExists = psql(`SELECT id FROM users WHERE email = '${LINK_USER_EMAIL}'`);
    if (!linkUserExists) {
      const hash = bcryptHash('linktest1234');
      psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${LINK_USER_EMAIL}', '${hash}', true)`);
    }

    const linkUserId = psql(`SELECT id FROM users WHERE email = '${LINK_USER_EMAIL}'`);
    expect(linkUserId).toBeTruthy();

    // Insert an entry belonging to link-test user directly in DB
    const today = new Date().toISOString().split('T')[0];
    psql(`INSERT INTO calorie_entries (user_id, entry_name, amount, entry_date) VALUES (${linkUserId}, 'security-test-entry', 999, '${today}')`);
    const entryId = psql(`SELECT id FROM calorie_entries WHERE user_id = ${linkUserId} AND entry_name = 'security-test-entry' ORDER BY id DESC LIMIT 1`);
    expect(entryId).toBeTruthy();

    // Get a valid CSRF token
    const csrfRes = await page.request.get('/api/csrf');
    const { token } = await csrfRes.json();

    // As test user, try to delete link-test user's entry
    const response = await page.request.post(`/entries/${entryId}/delete`, {
      headers: { 'X-CSRF-Token': token },
    });

    // Should be 404 (entry not found for current user) or 403 (forbidden)
    expect([403, 404]).toContain(response.status());

    // Verify the entry still exists in DB
    const stillExists = psql(`SELECT id FROM calorie_entries WHERE id = ${entryId} AND user_id = ${linkUserId}`);
    expect(stillExists).toBeTruthy();

    // Cleanup
    psql(`DELETE FROM calorie_entries WHERE id = ${entryId}`);
  });

  test.skip('cannot access linked user data without active link', async ({ page }) => {
    await login(page);

    const testUserId = psql(`SELECT id FROM users WHERE email = '${TEST_USER_EMAIL}'`);
    const linkUserId = psql(`SELECT id FROM users WHERE email = '${LINK_USER_EMAIL}'`);

    // Ensure no active link exists between test and link-test users
    if (testUserId && linkUserId) {
      psql(`DELETE FROM account_links WHERE
        (requester_id = ${testUserId} AND target_id = ${linkUserId}) OR
        (requester_id = ${linkUserId} AND target_id = ${testUserId})`);
    }

    // Attempt to fetch entries for link-test user without a link
    const today = new Date().toISOString().split('T')[0];
    const response = await page.request.get(`/entries/day?userId=${linkUserId}&date=${today}`);

    // Should be 403 (not linked) or 404
    expect([403, 404]).toContain(response.status());
  });

  test('session cookie is httpOnly', async ({ page }) => {
    await login(page);

    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find((c) => c.name === 'schautrack.sid');

    expect(sessionCookie).toBeDefined();
    expect(sessionCookie!.httpOnly).toBe(true);
  });

  test('session cookie has sameSite lax or strict', async ({ page }) => {
    await login(page);

    const cookies = await page.context().cookies();
    const sessionCookie = cookies.find((c) => c.name === 'schautrack.sid');

    expect(sessionCookie).toBeDefined();
    // SameSite must be Lax or Strict — never None (which would allow cross-site requests)
    expect(['Lax', 'Strict']).toContain(sessionCookie!.sameSite);
  });

  test('failed login returns 401 not 429 under normal conditions', async ({ page }) => {
    // This confirms the rate limiter isn't falsely triggering for normal usage.
    // Login requires a CSRF token, so fetch one first from the login page context.
    const context = await page.context().browser()!.newContext({ storageState: { cookies: [], origins: [] } });
    const freshPage = await context.newPage();

    // Visiting the page sets up a session so we can fetch a CSRF token
    await freshPage.goto('/login');
    await freshPage.waitForLoadState('domcontentloaded');

    const csrfRes = await freshPage.request.get('/api/csrf');
    const { token } = await csrfRes.json();

    const response = await freshPage.request.post('/api/auth/login', {
      data: { email: 'nobody@example.com', password: 'wrongpassword' },
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
      },
    });

    // Should be 401 (bad credentials), NOT 429 (rate limit)
    expect(response.status()).toBe(401);
    expect(response.status()).not.toBe(429);

    await context.close();
  });

  test('unauthenticated API requests return 401', async ({ page }) => {
    // Fresh context — no session
    const context = await page.context().browser()!.newContext({ storageState: { cookies: [], origins: [] } });
    const freshPage = await context.newPage();

    const response = await freshPage.request.get('/api/me');
    expect(response.status()).toBe(401);

    await context.close();
  });

  test('cannot access admin routes as non-admin user', async ({ page }) => {
    await login(page);

    // As a non-admin user, GET /admin/invites should return 403
    const response = await page.request.get('/admin/invites');
    expect(response.status()).toBe(403);
  });

  test('API returns 401 for protected endpoints without session', async ({ page }) => {
    const context = await page.context().browser()!.newContext({ storageState: { cookies: [], origins: [] } });
    const freshPage = await context.newPage();

    // Dashboard data endpoint requires login
    const dashResponse = await freshPage.request.get('/api/dashboard');
    expect(dashResponse.status()).toBe(401);

    await context.close();
  });
});
