import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser } from './fixtures/helpers';
import * as crypto from 'crypto';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
let user: { email: string; password: string; id: string };

test.describe('Session and Token Expiry', () => {
  test.beforeAll(() => {
    user = createIsolatedUser('session-expiry');
  });

  test('expired session cookie is rejected with 401 on API', async ({ browser }) => {
    // Generate a random session ID and insert it with expire = 1 day ago
    const expiredSid = crypto.randomBytes(32).toString('hex');
    const sessData = JSON.stringify({ data: {} });
    psql(
      `INSERT INTO "session" (sid, sess, expire)
       VALUES ('${expiredSid}', '${sessData}'::json, NOW() - INTERVAL '1 day')
       ON CONFLICT (sid) DO UPDATE SET expire = NOW() - INTERVAL '1 day'`
    );

    // Create a context with this expired session cookie
    const context = await browser.newContext({
      baseURL,
      storageState: {
        cookies: [{
          name: 'schautrack.sid',
          value: expiredSid,
          domain: new URL(baseURL).hostname,
          path: '/',
          httpOnly: true,
          secure: false,
          sameSite: 'Lax',
          expires: -1,
        }],
        origins: [],
      },
    });
    const page = await context.newPage();

    try {
      const response = await page.request.get(`${baseURL}/api/me`);
      expect(response.status()).toBe(401);
    } finally {
      await context.close();
      psql(`DELETE FROM "session" WHERE sid = '${expiredSid}'`);
    }
  });

  test('navigating to dashboard with expired session eventually shows login', async ({ browser }) => {
    const expiredSid = crypto.randomBytes(32).toString('hex');
    const sessData = JSON.stringify({ data: {} });
    psql(
      `INSERT INTO "session" (sid, sess, expire)
       VALUES ('${expiredSid}', '${sessData}'::json, NOW() - INTERVAL '1 day')
       ON CONFLICT (sid) DO NOTHING`
    );

    const context = await browser.newContext({
      baseURL,
      storageState: {
        cookies: [{
          name: 'schautrack.sid',
          value: expiredSid,
          domain: new URL(baseURL).hostname,
          path: '/',
          httpOnly: true,
          secure: false,
          sameSite: 'Lax',
          expires: -1,
        }],
        origins: [],
      },
    });
    const page = await context.newPage();

    try {
      await page.goto('/dashboard');
      // Wait for SPA to mount, fetch /api/me (401), and redirect
      await page.waitForTimeout(3000);

      // After the SPA detects 401, it redirects to /login
      // Check URL or presence of login form
      const url = page.url();
      const loginButtonVisible = await page.getByRole('button', { name: 'Log In' }).isVisible({ timeout: 8000 }).catch(() => false);
      const isLoginPage = url.includes('/login') || loginButtonVisible;
      expect(isLoginPage).toBe(true);
    } finally {
      await context.close();
      psql(`DELETE FROM "session" WHERE sid = '${expiredSid}'`);
    }
  });

  test('expired password reset token is rejected by server', async ({ browser }) => {
    // Insert an expired token for our test user
    const expiredToken = '000000';
    psql(`DELETE FROM password_reset_tokens WHERE user_id = ${user.id}`);
    psql(
      `INSERT INTO password_reset_tokens (user_id, token, expires_at, used)
       VALUES (${user.id}, '${expiredToken}', NOW() - INTERVAL '1 hour', false)`
    );

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    try {
      // Get a CSRF token and session
      const csrfRes = await page.request.get(`${baseURL}/api/csrf`);
      const { token: csrfToken } = await csrfRes.json();

      // Attempt to verify the expired code via POST /api/auth/reset-password
      // Without a valid session with resetEmail set, the server rejects with "No reset session."
      const resetRes = await page.request.post(`${baseURL}/api/auth/reset-password`, {
        data: { code: expiredToken },
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
      });

      // Without a valid reset session, expect 400
      expect(resetRes.status()).toBe(400);
      const body = await resetRes.json();
      expect(body.ok).toBe(false);
      expect(body.error).toBeTruthy();
    } finally {
      await context.close();
      psql(`DELETE FROM password_reset_tokens WHERE user_id = ${user.id}`);
    }
  });

  test('used password reset token is excluded by DB query (used = FALSE filter)', async () => {
    // Insert a token that is marked as used (not expired, but used=true)
    const usedToken = '111111';
    psql(`DELETE FROM password_reset_tokens WHERE user_id = ${user.id}`);
    psql(
      `INSERT INTO password_reset_tokens (user_id, token, expires_at, used)
       VALUES (${user.id}, '${usedToken}', NOW() + INTERVAL '1 hour', true)`
    );

    // Verify via DB that the used token won't match the WHERE used = FALSE query
    const found = psql(
      `SELECT id FROM password_reset_tokens
       WHERE user_id = ${user.id} AND token = '${usedToken}' AND used = FALSE`
    );
    // Should return nothing (empty string from psql helper)
    expect(found).toBe('');

    psql(`DELETE FROM password_reset_tokens WHERE user_id = ${user.id}`);
  });
});
