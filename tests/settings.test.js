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
