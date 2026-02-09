const app = require('../src/app');
const { pool } = require('../src/db/pool');
const { beforeAll, afterAll } = require('@jest/globals');

// Test database setup
beforeAll(async () => {
  // Use test database if DATABASE_URL is configured for tests
  // Otherwise skip database-dependent tests gracefully
  if (!process.env.DATABASE_URL) {
    console.warn('DATABASE_URL not set - database tests will be skipped');
  }
});

afterAll(async () => {
  // Clean up database connections
  if (pool) {
    await pool.end();
  }
});

module.exports = { app };