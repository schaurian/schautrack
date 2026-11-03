import { describe, it, expect } from 'vitest';
import { formatNumber, formatDate, formatRelativeTime } from './format';

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

describe('formatRelativeTime', () => {
  const now = new Date('2026-11-03T12:00:00Z');
  const ago = (seconds: number) => new Date(now.getTime() - seconds * 1000);

  it('picks the largest unit that keeps the number at least one', () => {
    expect(formatRelativeTime(ago(0), now, 'en')).toBe('now');
    expect(formatRelativeTime(ago(30), now, 'en')).toBe('30 seconds ago');
    expect(formatRelativeTime(ago(5 * 60), now, 'en')).toBe('5 minutes ago');
    expect(formatRelativeTime(ago(3 * 3600), now, 'en')).toBe('3 hours ago');
    expect(formatRelativeTime(ago(86400), now, 'en')).toBe('1 day ago');
    expect(formatRelativeTime(ago(3 * 86400), now, 'en')).toBe('3 days ago');
    expect(formatRelativeTime(ago(60 * 86400), now, 'en')).toBe('2 months ago');
    expect(formatRelativeTime(ago(800 * 86400), now, 'en')).toBe('2 years ago');
  });

  it('never shows a full unit as the smaller one (59.6s is a minute, not "60 seconds")', () => {
    expect(formatRelativeTime(ago(59.6), now, 'en')).toBe('1 minute ago');
  });

  // Elapsed time, not calendar words: numeric:'auto' turned 36h into
  // "vorgestern" and 350 days into "last year", which reads oddly after
  // "Last login".
  it('counts elapsed time instead of naming calendar days, months or years', () => {
    expect(formatRelativeTime(ago(36 * 3600), now, 'en')).toBe('2 days ago');
    expect(formatRelativeTime(ago(36 * 3600), now, 'de')).toBe('vor 2 Tagen');
    expect(formatRelativeTime(ago(40 * 86400), now, 'en')).toBe('1 month ago');
    expect(formatRelativeTime(ago(40 * 86400), now, 'de')).toBe('vor 1 Monat');
    expect(formatRelativeTime(ago(350 * 86400), now, 'en')).toBe('1 year ago');
    expect(formatRelativeTime(ago(350 * 86400), now, 'de')).toBe('vor 1 Jahr');
  });

  it('shows a future time (clock skew) and the present as "now", never "in 5 minutes"', () => {
    expect(formatRelativeTime(ago(-300), now, 'en')).toBe('now');
    expect(formatRelativeTime(ago(-3 * 86400), now, 'en')).toBe('now');
    expect(formatRelativeTime(ago(0.2), now, 'en')).toBe('now');
    expect(formatRelativeTime(ago(-300), now, 'de')).toBe('jetzt');
  });

  it('is locale-aware', () => {
    expect(formatRelativeTime(ago(3 * 86400), now, 'de')).toBe('vor 3 Tagen');
    expect(formatRelativeTime(ago(3 * 86400), now, 'fr')).toBe('il y a 3 jours');
  });
});
