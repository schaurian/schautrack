const { describe, test, expect, beforeAll } = require('@jest/globals');
const request = require('supertest');
const { createTestApp } = require('./setup');

const entriesRoutes = require('../src/routes/entries');

let app;

beforeAll(() => {
  app = createTestApp(entriesRoutes);
});

describe('Entries — authentication required', () => {
  test('GET /dashboard redirects to /login', async () => {
    await request(app)
      .get('/dashboard')
      .expect(302)
      .expect('Location', '/login');
  });

  test('POST /entries redirects to /login', async () => {
    await request(app)
      .post('/entries')
      .send({ amount: '100' })
      .expect(302)
      .expect('Location', '/login');
  });

  test('GET /overview redirects to /login', async () => {
    await request(app)
      .get('/overview')
      .expect(302)
      .expect('Location', '/login');
  });

  test('GET /entries/day redirects to /login', async () => {
    await request(app)
      .get('/entries/day?date=2024-01-01')
      .expect(302)
      .expect('Location', '/login');
  });

  test('GET /settings/export redirects to /login', async () => {
    await request(app)
      .get('/settings/export')
      .expect(302)
      .expect('Location', '/login');
  });

  test('POST /settings/import redirects to /login', async () => {
    await request(app)
      .post('/settings/import')
      .expect(302)
      .expect('Location', '/login');
  });

  test('POST /goal redirects to /login', async () => {
    await request(app)
      .post('/goal')
      .send({ goal: '2000' })
      .expect(302)
      .expect('Location', '/login');
  });
});
