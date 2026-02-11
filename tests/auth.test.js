const { describe, test, expect, beforeAll, afterAll } = require('@jest/globals');
const request = require('supertest');
const { app } = require('./setup');
const { pool } = require('../src/db/pool');

describe('Authentication', () => {
  let testUserId;

  const skipIfNoDb = () => {
    if (!process.env.DATABASE_URL) {
      console.log('Skipping database test - DATABASE_URL not set');
      return true;
    }
    return false;
  };

  afterAll(async () => {
    // Clean up test user if created
    if (testUserId && process.env.DATABASE_URL) {
      try {
        await pool.query('DELETE FROM users WHERE id = $1', [testUserId]);
      } catch (err) {
        console.warn('Failed to clean up test user:', err.message);
      }
    }
  });

  describe('GET /register', () => {
    test('should render registration page', async () => {
      const response = await request(app)
        .get('/register')
        .expect(200);
      
      expect(response.text).toContain('Register');
      expect(response.text).toContain('email');
      expect(response.text).toContain('password');
    });
  });

  describe('GET /login', () => {
    test('should render login page', async () => {
      const response = await request(app)
        .get('/login')
        .expect(200);
      
      expect(response.text).toContain('Login');
      expect(response.text).toContain('email');
      expect(response.text).toContain('password');
    });
  });

  describe('POST /register', () => {
    test('should reject registration without email', async () => {
      if (skipIfNoDb()) return;

      const response = await request(app)
        .post('/register')
        .send({
          step: 'credentials',
          password: 'testpassword123',
          _csrf: 'dummy' // In real tests, you'd get this from the form
        })
        .expect(200);
      
      expect(response.text).toContain('Email and password are required');
    });

    test('should reject short password', async () => {
      if (skipIfNoDb()) return;

      const response = await request(app)
        .post('/register')
        .send({
          step: 'credentials',
          email: 'test@example.com',
          password: 'short',
          _csrf: 'dummy'
        })
        .expect(200);
      
      expect(response.text).toContain('Password must be at least 10 characters');
    });
  });

  describe('POST /login', () => {
    test('should reject login without credentials', async () => {
      if (skipIfNoDb()) return;

      const response = await request(app)
        .post('/login')
        .send({
          _csrf: 'dummy'
        })
        .expect(200);
      
      expect(response.text).toContain('Email and password are required');
    });

    test('should reject invalid credentials', async () => {
      if (skipIfNoDb()) return;

      const response = await request(app)
        .post('/login')
        .send({
          email: 'nonexistent@example.com',
          password: 'wrongpassword',
          _csrf: 'dummy'
        })
        .expect(200);
      
      expect(response.text).toContain('Invalid credentials');
    });
  });

  describe('GET /dashboard', () => {
    test('should redirect to login when not authenticated', async () => {
      await request(app)
        .get('/dashboard')
        .expect(302)
        .expect('Location', '/login');
    });
  });

  describe('GET /', () => {
    test('should render landing page', async () => {
      const response = await request(app)
        .get('/')
        .expect(200);
      
      expect(response.text).toContain('Schautrack');
    });
  });

  describe('Password Reset Flow', () => {
    test('should render forgot password page', async () => {
      const response = await request(app)
        .get('/forgot-password')
        .expect(200);
      
      expect(response.text).toContain('Forgot Password');
      expect(response.text).toContain('email');
    });

    test('should render reset password page with session', async () => {
      // This would require setting up session data, skip for now
      const response = await request(app)
        .get('/reset-password')
        .expect(302); // Should redirect without session
      
      expect(response.headers.location).toBe('/forgot-password');
    });
  });
});