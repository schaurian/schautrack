const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const request = require('supertest');
const express = require('express');

// Mock the pool before requiring the health route
jest.mock('../src/db/pool', () => {
  const mockPool = {
    query: jest.fn(),
    totalCount: 5,
    idleCount: 3,
    waitingCount: 0,
  };
  return { pool: mockPool };
});

const { pool } = require('../src/db/pool');

describe('GET /api/health', () => {
  let app;

  beforeEach(() => {
    // Re-import fresh module to reset shuttingDown state
    jest.resetModules();
    jest.mock('../src/db/pool', () => ({
      pool: {
        query: jest.fn(),
        totalCount: 5,
        idleCount: 3,
        waitingCount: 0,
      },
    }));

    const healthRoutes = require('../src/routes/health');
    app = express();
    app.use('/api', healthRoutes);
  });

  test('returns 200 with status ok when DB is connected', async () => {
    const { pool: mockPool } = require('../src/db/pool');
    mockPool.query.mockResolvedValue({ rows: [{ '?column?': 1 }] });

    const res = await request(app).get('/api/health').expect(200);

    expect(res.body.app).toBe('schautrack');
    expect(res.body.status).toBe('ok');
    expect(res.body.version).toBeDefined();
    expect(res.body.pool).toBeDefined();
    expect(res.body.pool.totalCount).toBe(5);
    expect(res.body.pool.idleCount).toBe(3);
    expect(res.body.pool.waitingCount).toBe(0);
  });

  test('returns 503 when DB query fails', async () => {
    const { pool: mockPool } = require('../src/db/pool');
    mockPool.query.mockRejectedValue(new Error('connection refused'));

    const res = await request(app).get('/api/health').expect(503);

    expect(res.body.app).toBe('schautrack');
    expect(res.body.status).toBe('error');
  });

  test('returns 503 when app is shutting down', async () => {
    const healthRoutes = require('../src/routes/health');
    healthRoutes.markShuttingDown();

    const res = await request(app).get('/api/health').expect(503);

    expect(res.body.app).toBe('schautrack');
    expect(res.body.status).toBe('shutting_down');
  });
});
