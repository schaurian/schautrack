const { describe, test, expect } = require('@jest/globals');
const request = require('supertest');
const { app } = require('./setup');

describe('Weight Entries', () => {
  const skipIfNoDb = () => {
    if (!process.env.DATABASE_URL) {
      console.log('Skipping database test - DATABASE_URL not set');
      return true;
    }
    return false;
  };

  describe('GET /weight/day', () => {
    test('should require authentication', async () => {
      await request(app)
        .get('/weight/day?date=2024-01-01')
        .expect(302)
        .expect('Location', '/login');
    });
  });

  describe('POST /weight/upsert', () => {
    test('should require authentication', async () => {
      await request(app)
        .post('/weight/upsert')
        .send({
          weight: '70.5',
          date: '2024-01-01'
        })
        .expect(302)
        .expect('Location', '/login');
    });
  });

  describe('POST /weight/:id/delete', () => {
    test('should require authentication', async () => {
      await request(app)
        .post('/weight/1/delete')
        .expect(302)
        .expect('Location', '/login');
    });
  });

  describe('Weight parsing', () => {
    test('should handle various weight formats', () => {
      const { parseWeight } = require('../src/lib/utils');

      // Valid weights
      expect(parseWeight('70.5')).toEqual({ ok: true, value: 70.5 });
      expect(parseWeight('70,5')).toEqual({ ok: true, value: 70.5 }); // European format
      expect(parseWeight('155')).toEqual({ ok: true, value: 155 });
      expect(parseWeight(' 68.2 ')).toEqual({ ok: true, value: 68.2 });

      // Invalid weights
      expect(parseWeight('')).toEqual({ ok: false, value: null });
      expect(parseWeight('abc')).toEqual({ ok: false, value: null });
      expect(parseWeight('-10')).toEqual({ ok: false, value: null });
      expect(parseWeight('0')).toEqual({ ok: false, value: null });
      expect(parseWeight('1600')).toEqual({ ok: false, value: null }); // Too high
      expect(parseWeight(null)).toEqual({ ok: false, value: null });
      expect(parseWeight(undefined)).toEqual({ ok: false, value: null });
    });
  });

  describe('Weight unit conversion', () => {
    test('should convert kg to lbs correctly', () => {
      const { kgToLbs, lbsToKg } = require('../src/lib/utils');

      // kg to lbs
      expect(kgToLbs(70)).toBeCloseTo(154.3, 1);
      expect(kgToLbs(100)).toBeCloseTo(220.5, 1);
      expect(kgToLbs(0)).toBe(0);
      expect(kgToLbs(null)).toBe(null);

      // lbs to kg
      expect(lbsToKg(154.3)).toBeCloseTo(70, 1);
      expect(lbsToKg(220.5)).toBeCloseTo(100, 1);
      expect(lbsToKg('0')).toBe(null);
      expect(lbsToKg('-10')).toBe(null);
      expect(lbsToKg('abc')).toBe(null);
    });
  });
});