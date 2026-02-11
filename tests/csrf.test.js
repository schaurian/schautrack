const { describe, test, expect } = require('@jest/globals');
const { generateCsrfToken, validateCsrfToken } = require('../src/middleware/csrf');

const mockReq = (session = {}, body = {}, headers = {}) => ({
  session,
  body,
  headers,
});

describe('generateCsrfToken', () => {
  test('creates a 64-char hex token', () => {
    const req = mockReq();
    const token = generateCsrfToken(req);
    expect(token).toMatch(/^[a-f0-9]{64}$/);
  });

  test('stores token in session', () => {
    const session = {};
    const req = mockReq(session);
    const token = generateCsrfToken(req);
    expect(session.csrfToken).toBe(token);
  });

  test('reuses existing session token', () => {
    const session = { csrfToken: 'existing-token' };
    const req = mockReq(session);
    expect(generateCsrfToken(req)).toBe('existing-token');
  });

  test('returns empty string without session', () => {
    expect(generateCsrfToken({ session: null })).toBe('');
  });
});

describe('validateCsrfToken', () => {
  test('validates matching token from body', () => {
    const token = 'a'.repeat(64);
    const req = mockReq({ csrfToken: token }, { _csrf: token });
    expect(validateCsrfToken(req)).toBe(true);
  });

  test('validates matching token from header', () => {
    const token = 'b'.repeat(64);
    const req = mockReq({ csrfToken: token }, {}, { 'x-csrf-token': token });
    expect(validateCsrfToken(req)).toBe(true);
  });

  test('rejects mismatched token', () => {
    const req = mockReq(
      { csrfToken: 'a'.repeat(64) },
      { _csrf: 'b'.repeat(64) }
    );
    expect(validateCsrfToken(req)).toBe(false);
  });

  test('rejects when no token submitted', () => {
    const req = mockReq({ csrfToken: 'a'.repeat(64) });
    expect(validateCsrfToken(req)).toBe(false);
  });

  test('rejects when no session token', () => {
    const req = mockReq({}, { _csrf: 'a'.repeat(64) });
    expect(validateCsrfToken(req)).toBe(false);
  });

  test('rejects different length tokens', () => {
    const req = mockReq(
      { csrfToken: 'a'.repeat(64) },
      { _csrf: 'a'.repeat(32) }
    );
    expect(validateCsrfToken(req)).toBe(false);
  });
});
