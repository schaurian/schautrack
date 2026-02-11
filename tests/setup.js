// Set env vars BEFORE any app modules are imported.
// pg.Pool is lazy — it won't actually connect until a query is made.
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgresql://test:test@localhost:5432/test';
process.env.SESSION_SECRET = 'test-session-secret-long-enough-for-testing';

const path = require('path');
const express = require('express');
const session = require('express-session');

const { attachUser } = require('../src/middleware/auth');
const { addCsrfToken } = require('../src/middleware/csrf');

// ---------------------------------------------------------------------------
// Test app factory
// ---------------------------------------------------------------------------
// Builds an Express app with the same middleware stack as production but
// uses MemoryStore for sessions (no PgSession) and stubs the settings
// middleware.  Routes still import pool.js but no queries fire unless a
// test actually hits a DB-dependent path.
// ---------------------------------------------------------------------------

function createTestApp(...routeModules) {
  const app = express();

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, '..', 'src', 'views'));

  app.use(express.static(path.join(__dirname, '..', 'src', 'public')));
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json({ limit: '10mb' }));

  // In-memory session store (no PostgreSQL dependency)
  app.use(
    session({
      secret: 'test-secret',
      resave: false,
      saveUninitialized: true,
      cookie: { secure: false },
    })
  );

  // Production auth middleware (reads from session.userId → pool query).
  // For unauthenticated tests this just sets currentUser = null.
  // For authenticated tests the session is pre-populated so the DB lookup
  // will be attempted — those tests require DATABASE_URL to point at a real DB.
  app.use(attachUser);

  // Real CSRF middleware — same as production
  app.use(addCsrfToken);

  // Stub global template variables that views expect
  app.use((req, res, next) => {
    res.locals.buildVersion = null;
    res.locals.robotsIndex = false;
    res.locals.baseUrl = 'http://localhost:3000';
    res.locals.supportEmail = null;
    res.locals.enableLegal = false;
    res.locals.imprintUrl = '/imprint';
    next();
  });

  // Mount requested route modules
  for (const routes of routeModules) {
    app.use('/', routes);
  }

  return app;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Extract the CSRF token embedded in an HTML form response. */
function extractCsrfToken(html) {
  const match = html.match(/name="_csrf"\s+value="([^"]+)"/);
  return match ? match[1] : null;
}

/**
 * Return a supertest agent pre-loaded with a valid CSRF token.
 * Usage:
 *   const { agent, csrfToken } = await getAgentWithCsrf(app, '/login');
 *   await agent.post('/login').send({ ..., _csrf: csrfToken }).expect(200);
 */
async function getAgentWithCsrf(app, getPath) {
  const request = require('supertest');
  const agent = request.agent(app);
  const res = await agent.get(getPath);
  const csrfToken = extractCsrfToken(res.text);
  return { agent, csrfToken };
}

module.exports = { createTestApp, extractCsrfToken, getAgentWithCsrf };
