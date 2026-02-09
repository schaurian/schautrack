const { doubleCsrf } = require('csrf-csrf');

// CSRF Protection
const {
  invalidCsrfTokenError,
  generateToken,
  doubleCsrfProtection,
} = doubleCsrf({
  getSecret: () => process.env.SESSION_SECRET,
  cookieName: '__Host-schautrack.x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  },
  size: 64,
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
});

const addCsrfToken = (req, res, next) => {
  // Add CSRF token to response locals for templates
  res.locals.csrfToken = generateToken(req, res);
  next();
};

module.exports = {
  invalidCsrfTokenError,
  generateToken,
  doubleCsrfProtection,
  addCsrfToken
};