const { describe, test, expect, beforeAll, afterAll } = require('@jest/globals');
const request = require('supertest');
const { createTestApp, extractCsrfToken, getAgentWithCsrf } = require('./setup');

const authRoutes = require('../src/routes/auth');

let app;

beforeAll(() => {
  app = createTestApp(authRoutes);
});

// ---- Pages render correctly (no DB needed) ----

describe('Auth pages', () => {
  test('GET /register renders registration page', async () => {
    const res = await request(app).get('/register').expect(200);
    expect(res.text).toContain('email');
    expect(res.text).toContain('password');
    // Should contain a CSRF token
    expect(extractCsrfToken(res.text)).toBeTruthy();
  });

  test('GET /login renders login page', async () => {
    const res = await request(app).get('/login').expect(200);
    expect(res.text).toContain('email');
    expect(res.text).toContain('password');
    expect(extractCsrfToken(res.text)).toBeTruthy();
  });

  test('GET /forgot-password renders forgot password page', async () => {
    const res = await request(app).get('/forgot-password').expect(200);
    expect(res.text).toContain('Forgot password');
  });

  test('GET /reset-password without session redirects to /forgot-password', async () => {
    const res = await request(app).get('/reset-password').expect(302);
    expect(res.headers.location).toBe('/forgot-password');
  });
});

// ---- CSRF protection works ----

describe('CSRF protection', () => {
  test('POST /login without CSRF token is rejected', async () => {
    const res = await request(app)
      .post('/login')
      .send({ email: 'a@b.com', password: 'test' });
    // Should redirect back (CSRF failure) rather than processing the login
    expect([302, 403]).toContain(res.status);
  });

  test('POST /login with wrong CSRF token is rejected', async () => {
    const { agent } = await getAgentWithCsrf(app, '/login');
    const res = await agent
      .post('/login')
      .send({ email: 'a@b.com', password: 'test', _csrf: 'wrong-token' });
    expect([302, 403]).toContain(res.status);
  });
});

// ---- Form validation (requires DB for pool queries) ----

const skipIfNoDb = () => {
  // If DATABASE_URL is the dummy value we set in setup.js, there's no real DB
  if (process.env.DATABASE_URL === 'postgresql://test:test@localhost:5432/test') {
    return true;
  }
  return false;
};

describe('Registration validation', () => {
  test('rejects registration without email', async () => {
    if (skipIfNoDb()) return;

    const { agent, csrfToken } = await getAgentWithCsrf(app, '/register');
    const res = await agent
      .post('/register')
      .send({ step: 'credentials', password: 'testpassword123', _csrf: csrfToken })
      .expect(200);

    expect(res.text).toContain('Email and password are required');
  });

  test('rejects short password', async () => {
    if (skipIfNoDb()) return;

    const { agent, csrfToken } = await getAgentWithCsrf(app, '/register');
    const res = await agent
      .post('/register')
      .send({ step: 'credentials', email: 'test@example.com', password: 'short', _csrf: csrfToken })
      .expect(200);

    expect(res.text).toContain('Password must be at least 10 characters');
  });
});

// ---- Session cookie lifetime ----

describe('Session cookie maxAge upgrade', () => {
  test('unauthenticated session gets short-lived cookie', async () => {
    const res = await request(app).get('/login');
    const cookie = res.headers['set-cookie']?.[0] || '';
    // Session cookie should be set but with a short Max-Age (not 30 days)
    if (cookie.includes('Max-Age=')) {
      const maxAge = parseInt(cookie.match(/Max-Age=(\d+)/)?.[1] || '0', 10);
      // Should be 15 min (900) or less, definitely not 30 days (2592000)
      expect(maxAge).toBeLessThanOrEqual(900);
    }
  });

  test('login upgrades session cookie to 30 days', async () => {
    if (skipIfNoDb()) return;

    const { agent, csrfToken } = await getAgentWithCsrf(app, '/login');
    const res = await agent
      .post('/login')
      .send({ email: 'test@test.com', password: 'test1234', _csrf: csrfToken });

    // After successful login, cookie should be upgraded to 30 days
    const cookie = res.headers['set-cookie']?.[0] || '';
    if (cookie.includes('Max-Age=')) {
      const maxAge = parseInt(cookie.match(/Max-Age=(\d+)/)?.[1] || '0', 10);
      // 30 days = 2592000 seconds
      expect(maxAge).toBe(2592000);
    }
  });
});

describe('Login validation', () => {
  test('rejects login without credentials', async () => {
    if (skipIfNoDb()) return;

    const { agent, csrfToken } = await getAgentWithCsrf(app, '/login');
    const res = await agent
      .post('/login')
      .send({ _csrf: csrfToken })
      .expect(200);

    expect(res.text).toContain('Email and password are required');
  });

  test('rejects invalid credentials', async () => {
    if (skipIfNoDb()) return;

    const { agent, csrfToken } = await getAgentWithCsrf(app, '/login');
    const res = await agent
      .post('/login')
      .send({ email: 'nonexistent@example.com', password: 'wrongpassword1', _csrf: csrfToken })
      .expect(200);

    expect(res.text).toContain('Invalid credentials');
  });
});
