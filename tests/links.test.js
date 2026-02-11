const { describe, test, expect, beforeAll } = require('@jest/globals');
const request = require('supertest');
const { createTestApp } = require('./setup');

const linksRoutes = require('../src/routes/links');

let app;

beforeAll(() => {
  app = createTestApp(linksRoutes);
});

describe('Account Linking — authentication required', () => {
  test('POST /settings/link/request redirects to /login', async () => {
    await request(app)
      .post('/settings/link/request')
      .send({ email: 'other@example.com' })
      .expect(302)
      .expect('Location', '/login');
  });

  test('POST /settings/link/respond redirects to /login', async () => {
    await request(app)
      .post('/settings/link/respond')
      .send({ request_id: '1', action: 'accept' })
      .expect(302)
      .expect('Location', '/login');
  });

  test('POST /settings/link/remove redirects to /login', async () => {
    await request(app)
      .post('/settings/link/remove')
      .send({ link_id: '1' })
      .expect(302)
      .expect('Location', '/login');
  });

  test('POST /links/:id/label redirects to /login or returns 401', async () => {
    const res = await request(app)
      .post('/links/1/label')
      .send({ label: 'Family' });

    expect([302, 401]).toContain(res.status);
  });
});
