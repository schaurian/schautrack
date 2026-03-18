const { describe, test, expect, beforeAll } = require('@jest/globals');
const request = require('supertest');
const { createTestApp } = require('./setup');

const settingsRoutes = require('../src/routes/settings');

let app;

beforeAll(() => {
  app = createTestApp(settingsRoutes);
});

describe('Settings — authentication required', () => {
  test('POST /settings/macros redirects to /login', async () => {
    await request(app)
      .post('/settings/macros')
      .send({ calorie_goal: '2000' })
      .expect(302)
      .expect('Location', '/login');
  });

  test('POST /settings/preferences redirects to /login', async () => {
    await request(app)
      .post('/settings/preferences')
      .send({ weight_unit: 'kg' })
      .expect(302)
      .expect('Location', '/login');
  });

  test('POST /settings/ai redirects to /login', async () => {
    await request(app)
      .post('/settings/ai')
      .send({ ai_key: 'test' })
      .expect(302)
      .expect('Location', '/login');
  });
});

// ---------------------------------------------------------------------------
// Password change + TOTP tests (mocked — no DB required)
// ---------------------------------------------------------------------------

describe('Password change with TOTP', () => {
  const express = require('express');
  const session = require('express-session');
  const speakeasy = require('speakeasy');

  // Generate a real TOTP secret for testing
  const totpSecret = speakeasy.generateSecret().base32;

  function buildApp({ totpEnabled = false } = {}) {
    // Use jest.doMock inside a fresh module scope
    jest.resetModules();

    const mockPool = {
      query: jest.fn(),
      on: jest.fn(),
    };

    jest.doMock('../src/db/pool', () => ({ pool: mockPool }));

    jest.doMock('../src/middleware/auth', () => ({
      requireLogin: (req, _res, next) => {
        req.currentUser = {
          id: 1,
          email: 'test@test.com',
          totp_enabled: totpEnabled,
          totp_secret: totpEnabled ? totpSecret : null,
          timezone: 'UTC',
          macros_enabled: {},
          macro_goals: {},
        };
        next();
      },
    }));

    // Mock argon2 — verify always succeeds, hash returns a dummy
    jest.doMock('argon2', () => ({
      verify: jest.fn(async () => true),
      hash: jest.fn(async () => '$argon2-mock-hash'),
    }));

    // Skip CSRF validation for these focused tests
    jest.doMock('../src/middleware/csrf', () => ({
      csrfProtection: (_req, _res, next) => next(),
    }));

    const routes = require('../src/routes/settings');

    const testApp = express();
    testApp.use(express.urlencoded({ extended: false }));
    // Provide a minimal session object for feedback storage
    testApp.use((req, _res, next) => {
      req.session = req.session || {};
      next();
    });
    testApp.use('/', routes);

    return { app: testApp, mockPool };
  }

  test('succeeds without TOTP when 2FA is not enabled', async () => {
    const { app: testApp, mockPool } = buildApp({ totpEnabled: false });
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ password_hash: 'hashed' }] })   // SELECT
      .mockResolvedValueOnce({ rows: [] });                              // UPDATE

    const res = await request(testApp)
      .post('/settings/password')
      .type('form')
      .send({
        current_password: 'oldpassword1',
        new_password: 'newpassword123',
        confirm_password: 'newpassword123',
      });

    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/settings');
    // UPDATE should have been called (password was changed)
    expect(mockPool.query).toHaveBeenCalledTimes(2);
  });

  test('rejects when 2FA is enabled and no TOTP code provided', async () => {
    const { app: testApp, mockPool } = buildApp({ totpEnabled: true });
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ password_hash: 'hashed' }] });   // SELECT

    const res = await request(testApp)
      .post('/settings/password')
      .type('form')
      .send({
        current_password: 'oldpassword1',
        new_password: 'newpassword123',
        confirm_password: 'newpassword123',
      });

    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/settings');
    // Only SELECT was called — no UPDATE (password was NOT changed)
    expect(mockPool.query).toHaveBeenCalledTimes(1);
  });

  test('rejects when 2FA is enabled and wrong TOTP code provided', async () => {
    const { app: testApp, mockPool } = buildApp({ totpEnabled: true });
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ password_hash: 'hashed' }] });   // SELECT

    const res = await request(testApp)
      .post('/settings/password')
      .type('form')
      .send({
        current_password: 'oldpassword1',
        new_password: 'newpassword123',
        confirm_password: 'newpassword123',
        totp_code: '000000',
      });

    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/settings');
    // Only SELECT — no UPDATE
    expect(mockPool.query).toHaveBeenCalledTimes(1);
  });

  test('succeeds when 2FA is enabled and correct TOTP code provided', async () => {
    const { app: testApp, mockPool } = buildApp({ totpEnabled: true });
    mockPool.query
      .mockResolvedValueOnce({ rows: [{ password_hash: 'hashed' }] })   // SELECT
      .mockResolvedValueOnce({ rows: [] });                              // UPDATE

    const validToken = speakeasy.totp({
      secret: totpSecret,
      encoding: 'base32',
    });

    const res = await request(testApp)
      .post('/settings/password')
      .type('form')
      .send({
        current_password: 'oldpassword1',
        new_password: 'newpassword123',
        confirm_password: 'newpassword123',
        totp_code: validToken,
      });

    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('/settings');
    // Both SELECT and UPDATE were called — password was changed
    expect(mockPool.query).toHaveBeenCalledTimes(2);
  });
});

// ---------------------------------------------------------------------------
// SSE broadcast on macros save
// ---------------------------------------------------------------------------

describe('Macros save broadcasts settings-change SSE', () => {
  const express = require('express');

  let mockBroadcast;

  function buildMacroApp() {
    jest.resetModules();

    const mockPool = {
      query: jest.fn().mockResolvedValue({ rows: [] }),
      on: jest.fn(),
    };

    mockBroadcast = jest.fn();

    jest.doMock('../src/db/pool', () => ({ pool: mockPool }));
    jest.doMock('../src/middleware/auth', () => ({
      requireLogin: (req, _res, next) => {
        req.currentUser = {
          id: 42,
          email: 'test@test.com',
          totp_enabled: false,
          timezone: 'UTC',
          macros_enabled: {},
          macro_goals: {},
        };
        next();
      },
    }));
    jest.doMock('../src/middleware/csrf', () => ({
      csrfProtection: (_req, _res, next) => next(),
    }));
    jest.doMock('../src/routes/sse', () => ({
      broadcastSettingsChange: mockBroadcast,
    }));

    const routes = require('../src/routes/settings');
    const testApp = express();
    testApp.use(express.urlencoded({ extended: false }));
    testApp.use((req, _res, next) => {
      req.session = req.session || {};
      next();
    });
    testApp.use('/', routes);

    return { app: testApp, mockPool };
  }

  test('calls broadcastSettingsChange with correct payload after macros save', async () => {
    const { app: testApp } = buildMacroApp();

    await request(testApp)
      .post('/settings/macros')
      .type('form')
      .send({
        calorie_goal: '2000',
        calories_enabled: 'on',
        protein_enabled: 'on',
        protein_goal: '150',
        protein_mode: 'target',
        goal_threshold: '15',
      })
      .set('Accept', 'application/json')
      .expect(200);

    expect(mockBroadcast).toHaveBeenCalledTimes(1);
    const [userId, payload] = mockBroadcast.mock.calls[0];
    expect(userId).toBe(42);
    expect(payload.caloriesEnabled).toBe(true);
    expect(payload.dailyGoal).toBe(2000);
    expect(payload.goalThreshold).toBe(15);
    expect(payload.enabledMacros).toContain('protein');
    expect(payload.macroGoals).toHaveProperty('calories', 2000);
    expect(payload.macroGoals).toHaveProperty('protein', 150);
    expect(payload.macroModes).toHaveProperty('protein', 'target');
  });
});
