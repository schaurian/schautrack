const crypto = require('crypto');

// Simple session-based CSRF protection
// Generates a random token, stores it in the session, and validates on POST

function generateCsrfToken(req) {
  if (!req.session) return '';
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

function validateCsrfToken(req) {
  const bodyToken = req.body?._csrf;
  const headerToken = req.headers['x-csrf-token'];
  const token = bodyToken || headerToken;
  if (!token || !req.session?.csrfToken) return false;
  const a = Buffer.from(token);
  const b = Buffer.from(req.session.csrfToken);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// Middleware: attach CSRF token to res.locals for templates
const addCsrfToken = (req, res, next) => {
  if (!req.session) return next();
  const hadToken = !!req.session.csrfToken;
  res.locals.csrfToken = generateCsrfToken(req);
  // Force session save if we just created a new token (needed with saveUninitialized: false)
  if (!hadToken && req.session.csrfToken) {
    req.session.save(() => next());
  } else {
    next();
  }
};

// Middleware: validate CSRF token on state-changing requests
const csrfProtection = (req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }
  if (!validateCsrfToken(req)) {
    const wantsJson = req.headers.accept?.includes('application/json');
    if (wantsJson) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    req.session.flashError = 'Invalid or expired form submission. Please try again.';
    return res.redirect('back');
  }
  next();
};

module.exports = {
  addCsrfToken,
  csrfProtection,
  generateCsrfToken,
  validateCsrfToken
};
