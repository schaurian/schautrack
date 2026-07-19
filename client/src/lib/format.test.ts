import { describe, it, expect } from 'vitest';
import { formatNumber, formatDate } from './format';

describe('formatNumber', () => {
  it('groups by locale', () => {
    expect(formatNumber(1234.5, 'en-US')).toBe('1,234.5');
    expect(formatNumber(1234.5, 'de')).toBe('1.234,5');
  });
});

describe('formatDate', () => {
  it('formats a fixed date per locale', () => {
    const iso = '2026-07-19T00:00:00Z';
    const opts: Intl.DateTimeFormatOptions = {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      timeZone: 'UTC',
    };
    expect(formatDate(iso, 'en-US', opts)).toBe('July 19, 2026');
    expect(formatDate(iso, 'de', opts)).toBe('19. Juli 2026');
  });
});
