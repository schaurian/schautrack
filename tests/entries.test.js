const { describe, test, expect } = require('@jest/globals');
const request = require('supertest');
const { app } = require('./setup');

describe('Entries', () => {
  const skipIfNoDb = () => {
    if (!process.env.DATABASE_URL) {
      console.log('Skipping database test - DATABASE_URL not set');
      return true;
    }
    return false;
  };

  describe('GET /dashboard', () => {
    test('should require authentication', async () => {
      await request(app)
        .get('/dashboard')
        .expect(302)
        .expect('Location', '/login');
    });
  });

  describe('POST /entries', () => {
    test('should require authentication', async () => {
      await request(app)
        .post('/entries')
        .send({
          amount: '100',
          _csrf: 'dummy'
        })
        .expect(302)
        .expect('Location', '/login');
    });
  });

  describe('GET /overview', () => {
    test('should require authentication', async () => {
      await request(app)
        .get('/overview')
        .expect(302)
        .expect('Location', '/login');
    });
  });

  describe('GET /entries/day', () => {
    test('should require authentication', async () => {
      await request(app)
        .get('/entries/day?date=2024-01-01')
        .expect(302)
        .expect('Location', '/login');
    });
  });

  describe('Export/Import', () => {
    test('GET /settings/export should require authentication', async () => {
      await request(app)
        .get('/settings/export')
        .expect(302)
        .expect('Location', '/login');
    });

    test('POST /settings/import should require authentication', async () => {
      await request(app)
        .post('/settings/import')
        .expect(302)
        .expect('Location', '/login');
    });
  });

  describe('Goal setting', () => {
    test('POST /goal should require authentication', async () => {
      await request(app)
        .post('/goal')
        .send({ goal: '2000' })
        .expect(302)
        .expect('Location', '/login');
    });
  });
});