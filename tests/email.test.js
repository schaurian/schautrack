const { describe, test, expect } = require('@jest/globals');
const { generateResetCode } = require('../src/lib/email');

describe('generateResetCode', () => {
  test('returns a 6-digit numeric string', () => {
    const code = generateResetCode();
    expect(code).toMatch(/^\d{6}$/);
  });

  test('returns codes in the range 100000–999999', () => {
    for (let i = 0; i < 100; i++) {
      const num = parseInt(generateResetCode(), 10);
      expect(num).toBeGreaterThanOrEqual(100000);
      expect(num).toBeLessThan(1000000);
    }
  });
});
