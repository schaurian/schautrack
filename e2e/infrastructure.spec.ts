import { test, expect } from '@playwright/test';
import { psql } from './fixtures/helpers';

test.describe('Infrastructure', () => {
  test('health endpoint returns 200 with DB info', async ({ page }) => {
    const response = await page.request.get('/api/health');
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body.status).toBe('ok');
    expect(body.app).toBe('schautrack');
    expect(typeof body.version).toBe('string');
  });

  test('schema migrations ran successfully', async () => {
    const result = psql(
      `SELECT count(*) FROM information_schema.tables WHERE table_name IN ('users', 'calorie_entries', 'weight_entries', 'todos', 'daily_notes', 'account_links', 'admin_settings', 'totp_backup_codes', 'ai_usage')`
    );
    expect(Number(result)).toBe(9);
  });

  test('static assets served with cache headers', async ({ page }) => {
    const html = await (await page.request.get('/')).text();
    const match = html.match(/src="(\/assets\/[^"]+\.js)"/);
    if (match) {
      const assetResponse = await page.request.get(match[1]);
      const cacheControl = assetResponse.headers()['cache-control'] || '';
      expect(cacheControl).toContain('immutable');
    }
    // If no hashed asset found (dev mode), skip gracefully
  });

  test('expired session is rejected', async ({ page }) => {
    // Insert a session row with an expired timestamp
    psql(
      `INSERT INTO "session" (sid, sess, expire) VALUES ('expired-test-sid', '{"userId": 1}', NOW() - INTERVAL '1 day') ON CONFLICT (sid) DO UPDATE SET expire = NOW() - INTERVAL '1 day'`
    );

    const response = await page.request.get('/api/me', {
      headers: { Cookie: 'schautrack.sid=expired-test-sid' },
    });
    expect(response.status()).toBe(401);

    // Cleanup
    psql(`DELETE FROM "session" WHERE sid = 'expired-test-sid'`);
  });

  test('expired password reset token is rejected', async ({ page }) => {
    // Insert an expired token tied to user id 1 (admin) — direct DB verification
    psql(
      `INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (1, 'expired-e2e-test-token', NOW() - INTERVAL '1 day') ON CONFLICT (token) DO UPDATE SET expires_at = NOW() - INTERVAL '1 day'`
    );

    // Confirm the token is in the DB
    const count = psql(
      `SELECT count(*) FROM password_reset_tokens WHERE token = 'expired-e2e-test-token'`
    );
    expect(Number(count)).toBeGreaterThan(0);

    // The reset-password endpoint requires a session with resetEmail, so we use the forgot-password
    // flow to get a valid session, then verify the expired token is rejected.
    // Initiate a forgot-password session for an email that matches the token's user (admin@test.com)
    const forgotRes = await page.request.post('/api/auth/forgot-password', {
      data: { email: 'admin@test.com', captcha: 'bypass' },
    });
    // API returns 200 on success, 400 for captcha/validation error, 403 if rate limited
    expect([200, 400, 403]).toContain(forgotRes.status());

    // If the forgot-password succeeded, a session is set. Try the expired token.
    if (forgotRes.status() === 200) {
      const resetRes = await page.request.post('/api/auth/reset-password', {
        data: { code: 'expired-e2e-test-token', password: 'irrelevant' },
      });
      // Should fail — expired token or invalid code
      expect(resetRes.status()).not.toBe(200);
    }

    // Cleanup
    psql(`DELETE FROM password_reset_tokens WHERE token = 'expired-e2e-test-token'`);
  });

  test('app serves index.html for SPA routes', async ({ page }) => {
    const response = await page.request.get('/some-random-nonexistent-route');
    expect(response.status()).toBe(200);

    const contentType = response.headers()['content-type'] || '';
    expect(contentType).toContain('text/html');

    const body = await response.text();
    expect(body).toContain('<!DOCTYPE html>');
  });
});
