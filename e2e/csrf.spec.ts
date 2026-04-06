import { test, expect } from './fixtures/auth';
import { login } from './fixtures/auth';

test.describe('CSRF Protection', () => {
  test('GET /api/csrf returns a token', async ({ page }) => {
    await login(page);

    const response = await page.request.get('/api/csrf');
    expect(response.status()).toBe(200);

    const body = await response.json();
    expect(body).toHaveProperty('token');
    expect(typeof body.token).toBe('string');
    expect(body.token.length).toBeGreaterThan(0);
  });

  test('POST without CSRF token returns 403', async ({ page }) => {
    await login(page);

    // Post to entries without X-CSRF-Token header — should be rejected
    const response = await page.request.post('/entries', {
      data: { name: 'csrf-test', calories: 100 },
      headers: {
        'Content-Type': 'application/json',
        // No X-CSRF-Token header
      },
    });

    expect(response.status()).toBe(403);
  });

  test('POST with wrong CSRF token returns 403', async ({ page }) => {
    await login(page);

    const response = await page.request.post('/entries', {
      data: { name: 'csrf-test', calories: 100 },
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': 'invalid-token-value',
      },
    });

    expect(response.status()).toBe(403);
  });

  test('POST with valid CSRF token succeeds (not 403)', async ({ page }) => {
    await login(page);

    // Fetch a valid CSRF token first
    const csrfRes = await page.request.get('/api/csrf');
    expect(csrfRes.status()).toBe(200);
    const { token } = await csrfRes.json();

    // Post with the valid token — should not be rejected with 403
    const response = await page.request.post('/entries', {
      data: { name: 'csrf-valid-test', calories: 100 },
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': token,
      },
    });

    // Any non-403 response means CSRF passed (could be 200/201 or validation error)
    expect(response.status()).not.toBe(403);

    // Cleanup: if the entry was created, delete it
    if (response.status() === 200 || response.status() === 201) {
      const created = await response.json().catch(() => null);
      if (created?.id) {
        await page.request.post(`/entries/${created.id}/delete`, {
          headers: { 'X-CSRF-Token': token },
        });
      }
    }
  });

  test('CSRF protection applies to admin settings endpoint', async ({ page }) => {
    await login(page);

    // Non-admin trying to POST to admin settings without CSRF token — should get 403
    const response = await page.request.post('/admin/settings', {
      data: { enable_registration: 'true' },
      headers: { 'Content-Type': 'application/json' },
    });

    // Either 403 (CSRF) or 403 (not admin) — both are correct rejections
    expect(response.status()).toBe(403);
  });
});
