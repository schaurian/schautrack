const { describe, test, expect, beforeAll } = require('@jest/globals');
const request = require('supertest');
const { createTestApp } = require('./setup');

const weightRoutes = require('../src/routes/weight');

let app;

beforeAll(() => {
  app = createTestApp(weightRoutes);
});

describe('Weight — authentication required', () => {
  test('GET /weight/day redirects to /login', async () => {
    await request(app)
      .get('/weight/day?date=2024-01-01')
      .expect(302)
      .expect('Location', '/login');
  });

  test('POST /weight/upsert redirects to /login', async () => {
    await request(app)
      .post('/weight/upsert')
      .send({ weight: '70.5', date: '2024-01-01' })
      .expect(302)
      .expect('Location', '/login');
  });

  test('POST /weight/:id/delete redirects to /login', async () => {
    await request(app)
      .post('/weight/1/delete')
      .expect(302)
      .expect('Location', '/login');
  });
});

describe('Weight parsing (unit tests)', () => {
  const { parseWeight } = require('../src/lib/utils');

  test('parses valid weights', () => {
    expect(parseWeight('70.5')).toEqual({ ok: true, value: 70.5 });
    expect(parseWeight('70,5')).toEqual({ ok: true, value: 70.5 });
    expect(parseWeight('155')).toEqual({ ok: true, value: 155 });
    expect(parseWeight(' 68.2 ')).toEqual({ ok: true, value: 68.2 });
  });

  test('rejects invalid weights', () => {
    expect(parseWeight('')).toEqual({ ok: false, value: null });
    expect(parseWeight('abc')).toEqual({ ok: false, value: null });
    expect(parseWeight('-10')).toEqual({ ok: false, value: null });
    expect(parseWeight('0')).toEqual({ ok: false, value: null });
    expect(parseWeight('1600')).toEqual({ ok: false, value: null });
    expect(parseWeight(null)).toEqual({ ok: false, value: null });
    expect(parseWeight(undefined)).toEqual({ ok: false, value: null });
  });
});

describe('Weight unit conversion (unit tests)', () => {
  const { kgToLbs, lbsToKg } = require('../src/lib/utils');

  test('converts kg to lbs', () => {
    expect(kgToLbs(70)).toBeCloseTo(154.3, 1);
    expect(kgToLbs(100)).toBeCloseTo(220.5, 1);
    expect(kgToLbs(0)).toBe(0);
    expect(kgToLbs(null)).toBe(null);
  });

  test('converts lbs to kg', () => {
    expect(lbsToKg(154.3)).toBeCloseTo(70, 1);
    expect(lbsToKg(220.5)).toBeCloseTo(100, 1);
    expect(lbsToKg('0')).toBe(null);
    expect(lbsToKg('-10')).toBe(null);
    expect(lbsToKg('abc')).toBe(null);
  });
});
