const { describe, test, expect } = require('@jest/globals');
const { generateCaptcha, verifyCaptcha } = require('../src/lib/captcha');

describe('generateCaptcha', () => {
  test('returns object with text and data properties', () => {
    const captcha = generateCaptcha();
    expect(captcha).toHaveProperty('text');
    expect(captcha).toHaveProperty('data');
    expect(typeof captcha.text).toBe('string');
    expect(captcha.text.length).toBeGreaterThan(0);
    expect(captcha.data).toContain('<svg');
  });
});

describe('verifyCaptcha', () => {
  test('returns true for matching answers', () => {
    expect(verifyCaptcha('AbCdE', 'AbCdE')).toBe(true);
  });

  test('is case-insensitive', () => {
    expect(verifyCaptcha('AbCdE', 'abcde')).toBe(true);
    expect(verifyCaptcha('abcde', 'ABCDE')).toBe(true);
  });

  test('trims whitespace', () => {
    expect(verifyCaptcha('abc', '  abc  ')).toBe(true);
    expect(verifyCaptcha('  abc  ', 'abc')).toBe(true);
  });

  test('returns false for non-matching answers', () => {
    expect(verifyCaptcha('abc', 'xyz')).toBe(false);
  });

  test('returns false for missing inputs', () => {
    expect(verifyCaptcha(null, 'abc')).toBe(false);
    expect(verifyCaptcha('abc', null)).toBe(false);
    expect(verifyCaptcha(null, null)).toBe(false);
    expect(verifyCaptcha('', 'abc')).toBe(false);
    expect(verifyCaptcha('abc', '')).toBe(false);
  });
});
