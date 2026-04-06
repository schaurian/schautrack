import { test, expect } from '@playwright/test';
import { psql, bcryptHash } from './fixtures/helpers';

const BCRYPT_USER_EMAIL = 'bcrypt-migration-test@test.com';
const BCRYPT_USER_PASSWORD = 'migrationtest1234';

test.describe('Go Backend Migration', () => {
  test('users with bcrypt password hash can log in', async ({ browser }) => {
    // Create a user with a bcrypt hash (legacy format from old Node.js backend)
    const hash = bcryptHash(BCRYPT_USER_PASSWORD);

    const existing = psql(`SELECT id FROM users WHERE email = '${BCRYPT_USER_EMAIL}'`);
    if (existing) {
      psql(`UPDATE users SET password_hash = '${hash}', email_verified = true WHERE id = ${existing}`);
    } else {
      psql(`INSERT INTO users (email, password_hash, email_verified) VALUES ('${BCRYPT_USER_EMAIL}', '${hash}', true)`);
    }

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    try {
      await page.goto('/login');
      await page.waitForLoadState('domcontentloaded');
      await page.getByLabel('Email').fill(BCRYPT_USER_EMAIL);
      await page.getByLabel('Password').fill(BCRYPT_USER_PASSWORD);
      await page.getByRole('button', { name: 'Log In' }).click();
      await page.waitForURL('/dashboard', { timeout: 15000 });
      await expect(page).toHaveURL(/\/dashboard/);
    } finally {
      await context.close();
      psql(`DELETE FROM users WHERE email = '${BCRYPT_USER_EMAIL}'`);
    }
  });

  test('API responses have expected JSON shape', async ({ browser }) => {
    // Use a fresh context for unauthenticated tests, then an authenticated one
    const anonContext = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const anonPage = await anonContext.newPage();

    try {
      // GET /api/health → has status, app, version, pool fields
      const healthRes = await anonPage.request.get('/api/health');
      expect([200, 503]).toContain(healthRes.status());
      const health = await healthRes.json();
      expect(health).toHaveProperty('status');
      expect(health).toHaveProperty('app');
      expect(health).toHaveProperty('version');
      expect(health).toHaveProperty('pool');

      // GET /api/csrf → has token field (string)
      const csrfRes = await anonPage.request.get('/api/csrf');
      expect(csrfRes.status()).toBe(200);
      const csrf = await csrfRes.json();
      expect(csrf).toHaveProperty('token');
      expect(typeof csrf.token).toBe('string');
      expect(csrf.token.length).toBeGreaterThan(0);

      // POST /api/auth/login with wrong creds → has ok: false, error field
      const { token: csrfToken } = csrf;
      const loginRes = await anonPage.request.post('/auth/login', {
        data: { email: 'nobody@example.com', password: 'wrongpassword' },
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
      });
      expect(loginRes.status()).not.toBe(200);
      const loginBody = await loginRes.json();
      expect(loginBody).toHaveProperty('ok', false);
      expect(loginBody).toHaveProperty('error');
      expect(typeof loginBody.error).toBe('string');
    } finally {
      await anonContext.close();
    }

    // GET /api/me (authenticated) → has user object with id, email, timezone and isAdmin boolean
    // Use the stored auth state from the test user
    const authContext = await browser.newContext({
      storageState: 'e2e/.auth/user.json',
    });
    const authPage = await authContext.newPage();

    try {
      const meRes = await authPage.request.get('/api/me');
      expect(meRes.status()).toBe(200);
      const me = await meRes.json();
      expect(me).toHaveProperty('user');
      expect(me.user).toHaveProperty('id');
      expect(me.user).toHaveProperty('email');
      expect(me.user).toHaveProperty('timezone');
      expect(me).toHaveProperty('isAdmin');
      expect(typeof me.isAdmin).toBe('boolean');
    } finally {
      await authContext.close();
    }
  });

  test('error responses use correct { ok: false, error } format', async ({ browser }) => {
    const authContext = await browser.newContext({
      storageState: 'e2e/.auth/user.json',
    });
    const authPage = await authContext.newPage();

    try {
      // Fetch a valid CSRF token first
      const csrfRes = await authPage.request.get('/api/csrf');
      const { token } = await csrfRes.json();

      // POST to /api/entries with empty body → 400 with error message
      const emptyBodyRes = await authPage.request.post('/entries', {
        data: {},
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': token,
        },
      });
      expect(emptyBodyRes.status()).toBe(400);
      const emptyBodyJson = await emptyBodyRes.json();
      expect(emptyBodyJson).toHaveProperty('ok', false);
      expect(emptyBodyJson).toHaveProperty('error');
      expect(typeof emptyBodyJson.error).toBe('string');
      expect(emptyBodyJson.error.length).toBeGreaterThan(0);

      // GET /api/admin/settings as non-admin → 403 with error message
      const adminRes = await authPage.request.get('/admin/settings');
      expect(adminRes.status()).toBe(403);
      const adminJson = await adminRes.json();
      expect(adminJson).toHaveProperty('ok', false);
      expect(adminJson).toHaveProperty('error');
      expect(typeof adminJson.error).toBe('string');
    } finally {
      await authContext.close();
    }
  });

  test('no leftover Node.js src/ code is served', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    try {
      const oldPaths = [
        '/src/public/style.css',
        '/src/routes/auth.js',
        '/src/views/dashboard.ejs',
      ];

      for (const path of oldPaths) {
        const res = await page.request.get(path);
        expect(res.status(), `Expected 404 for ${path}`).toBe(404);
      }
    } finally {
      await context.close();
    }
  });

  test('session cookie is schautrack.sid, not connect.sid', async ({ browser }) => {
    // Use a fresh context to do a real login
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    try {
      await page.goto('/login');
      await page.waitForLoadState('domcontentloaded');
      await page.getByLabel('Email').fill('test@test.com');
      await page.getByLabel('Password').fill('test1234test');
      await page.getByRole('button', { name: 'Log In' }).click();
      await page.waitForURL('/dashboard', { timeout: 15000 });

      const cookies = await context.cookies();
      const cookieNames = cookies.map((c) => c.name);

      expect(cookieNames).toContain('schautrack.sid');
      expect(cookieNames).not.toContain('connect.sid');
    } finally {
      await context.close();
    }
  });

  test('CSRF token generation returns 64-char hex string', async ({ browser }) => {
    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await context.newPage();

    try {
      // Visit a page first to establish a session for the CSRF endpoint
      await page.goto('/login');
      await page.waitForLoadState('domcontentloaded');

      const res = await page.request.get('/api/csrf');
      expect(res.status()).toBe(200);

      const body = await res.json();
      expect(body).toHaveProperty('token');
      expect(typeof body.token).toBe('string');

      // CSRF token must be a 64-character lowercase hex string
      expect(body.token).toMatch(/^[0-9a-f]{64}$/);
    } finally {
      await context.close();
    }
  });
});
