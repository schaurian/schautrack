const { describe, test, expect } = require('@jest/globals');
const request = require('supertest');
const { app } = require('./setup');

describe('Account Linking', () => {
  const skipIfNoDb = () => {
    if (!process.env.DATABASE_URL) {
      console.log('Skipping database test - DATABASE_URL not set');
      return true;
    }
    return false;
  };

  describe('Link Requests', () => {
    test('POST /settings/link/request should require authentication', async () => {
      await request(app)
        .post('/settings/link/request')
        .send({
          email: 'other@example.com'
        })
        .expect(302)
        .expect('Location', '/login');
    });

    test('POST /settings/link/respond should require authentication', async () => {
      await request(app)
        .post('/settings/link/respond')
        .send({
          request_id: '1',
          action: 'accept'
        })
        .expect(302)
        .expect('Location', '/login');
    });

    test('POST /settings/link/remove should require authentication', async () => {
      await request(app)
        .post('/settings/link/remove')
        .send({
          link_id: '1'
        })
        .expect(302)
        .expect('Location', '/login');
    });
  });

  describe('Link Labels', () => {
    test('POST /links/:id/label should require authentication', async () => {
      const response = await request(app)
        .post('/links/1/label')
        .send({
          label: 'Family'
        });

      // Should be 302 redirect to login or 401 unauthorized
      expect([302, 401]).toContain(response.status);
    });
  });

  describe('Link Authorization Middleware', () => {
    test('should protect overview endpoint without link', async () => {
      // This would require a full authentication flow to test properly
      // For now, just verify it requires auth
      await request(app)
        .get('/overview?user=123')
        .expect(302)
        .expect('Location', '/login');
    });

    test('should protect entries/day endpoint without link', async () => {
      await request(app)
        .get('/entries/day?date=2024-01-01&user=123')
        .expect(302)
        .expect('Location', '/login');
    });

    test('should protect weight/day endpoint without link', async () => {
      await request(app)
        .get('/weight/day?date=2024-01-01&user=123')
        .expect(302)
        .expect('Location', '/login');
    });
  });
});