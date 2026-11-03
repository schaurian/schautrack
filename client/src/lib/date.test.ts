import { describe, it, expect, afterEach } from 'vitest';
import { followToday, isDateOnly, localDateStr, parseLocalDate } from './date';
import { formatDate } from './format';

// Node re-reads env.TZ on assignment, so each case runs in a real
// non-UTC zone even though CI itself runs in UTC. These are the zones where
// the stock idioms go wrong in opposite directions.
// src/ is type-checked without @types/node, hence the narrow cast.
const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } }).process.env;
const ZONES = ['America/Los_Angeles', 'Pacific/Auckland', 'Europe/Berlin', 'UTC'];
const originalTz = env.TZ;
afterEach(() => {
  env.TZ = originalTz;
});

describe.each(ZONES)('in %s', (zone) => {
  it('parseLocalDate keeps the calendar day, including month/year/DST boundaries', () => {
    env.TZ = zone;
    for (const ymd of ['2026-10-01', '2026-01-01', '2026-12-31', '2026-03-29', '2026-10-25', '2028-02-29']) {
      const d = parseLocalDate(ymd);
      expect(localDateStr(d)).toBe(ymd);
      expect(d.getHours()).toBe(0);
    }
  });

  it('formatDate shows a date-only string as that day, not the UTC instant', () => {
    env.TZ = zone;
    expect(formatDate('2026-10-01', 'en-US', { year: 'numeric', month: 'short', day: 'numeric' })).toBe('Oct 1, 2026');
    expect(formatDate('2027-01-01', 'en-US', { year: 'numeric', month: 'short', day: 'numeric' })).toBe('Jan 1, 2027');
  });
});

describe('localDateStr', () => {
  it('is the local date, not the UTC one, near midnight', () => {
    // 2026-11-03T19:00Z is 08:00 on Nov 4 in Auckland (NZDT, UTC+13).
    env.TZ = 'Pacific/Auckland';
    expect(localDateStr(new Date('2026-11-03T19:00:00Z'))).toBe('2026-11-04');
    // 2026-11-04T05:00Z is 21:00 on Nov 3 in Los Angeles (PST, UTC-8).
    env.TZ = 'America/Los_Angeles';
    expect(localDateStr(new Date('2026-11-04T05:00:00Z'))).toBe('2026-11-03');
    // Berlin's 25-hour day: 23:30 CET after the 2026-10-25 fall-back.
    env.TZ = 'Europe/Berlin';
    expect(localDateStr(new Date('2026-10-25T22:30:00Z'))).toBe('2026-10-25');
  });
});

describe('parseLocalDate / isDateOnly', () => {
  it('rejects anything but a bare date', () => {
    expect(isDateOnly('2026-10-01')).toBe(true);
    expect(isDateOnly('2026-10-01T00:00:00Z')).toBe(false);
    expect(Number.isNaN(parseLocalDate('2026-10-01T00:00:00Z').getTime())).toBe(true);
    expect(Number.isNaN(parseLocalDate('').getTime())).toBe(true);
  });
});

describe('followToday', () => {
  it.each([
    // [selected, prevToday, nextToday, expected]
    ['2026-11-03', '2026-11-03', '2026-11-04', '2026-11-04'], // was on today: follow midnight
    ['2026-12-31', '2026-12-31', '2027-01-01', '2027-01-01'], // across the year boundary
    ['2026-11-01', '2026-11-03', '2026-11-04', '2026-11-01'], // picked a past day: stay
    ['2026-11-03', '2026-11-03', '2026-11-03', '2026-11-03'], // same day refetch: no-op
    ['2026-11-03', undefined, '2026-11-04', '2026-11-03'], // first load: the server's selectedDate decides
  ])('selected=%s prev=%s next=%s → %s', (selected, prev, next, expected) => {
    expect(followToday(selected as string, prev as string | undefined, next as string)).toBe(expected);
  });
});
