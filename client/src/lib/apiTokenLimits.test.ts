import { describe, it, expect } from 'vitest';
import { isTokenExpired, activeTokenCount, isAtTokenLimit } from './apiTokenLimits';

const NOW = new Date('2026-06-15T12:00:00Z');
const PAST = '2026-01-01T00:00:00Z';
const FUTURE = '2027-01-01T00:00:00Z';

/** A token as the list endpoint returns it. */
const token = (expired?: boolean, expires_at: string | null = null) => ({ expired, expires_at });

describe('isTokenExpired', () => {
  // The server's clock is the one the limit is enforced against, so its answer
  // wins even when the browser would read the date the other way.
  it("trusts the server's flag over the browser's clock", () => {
    expect(isTokenExpired(token(true, FUTURE), NOW)).toBe(true);
    expect(isTokenExpired(token(false, PAST), NOW)).toBe(false);
  });

  it('falls back to expires_at when the server did not send the flag', () => {
    expect(isTokenExpired(token(undefined, PAST), NOW)).toBe(true);
    expect(isTokenExpired(token(undefined, FUTURE), NOW)).toBe(false);
  });

  it('treats a token with no expiry as live', () => {
    expect(isTokenExpired(token(undefined, null), NOW)).toBe(false);
    expect(isTokenExpired(token(false, null), NOW)).toBe(false);
  });

  it('expires exactly at the boundary, matching the server', () => {
    expect(isTokenExpired(token(undefined, NOW.toISOString()), NOW)).toBe(true);
  });
});

describe('activeTokenCount', () => {
  it('counts only the tokens that are not expired', () => {
    const tokens = [token(false), token(true), token(false), token(true)];
    expect(activeTokenCount(tokens, NOW)).toBe(2);
  });

  it('is 0 for an empty list', () => expect(activeTokenCount([], NOW)).toBe(0));
});

describe('isAtTokenLimit', () => {
  const many = (n: number, expired: boolean) => Array.from({ length: n }, () => token(expired));

  it('is at the limit when every token is live', () => {
    expect(isAtTokenLimit(many(20, false), 20, NOW)).toBe(true);
  });

  // The regression: 20 tokens of which 8 have lapsed leaves 12 live, so the
  // server would mint eight more. Gating on tokens.length hid the button.
  it('is NOT at the limit when expired tokens make up the difference', () => {
    const tokens = [...many(12, false), ...many(8, true)];
    expect(tokens.length).toBe(20);
    expect(isAtTokenLimit(tokens, 20, NOW)).toBe(false);
  });

  it('is at the limit once the live subset reaches max, however many are dead', () => {
    const tokens = [...many(20, false), ...many(5, true)];
    expect(isAtTokenLimit(tokens, 20, NOW)).toBe(true);
  });

  it('is not at the limit below max, and never for an empty list', () => {
    expect(isAtTokenLimit(many(19, false), 20, NOW)).toBe(false);
    expect(isAtTokenLimit([], 20, NOW)).toBe(false);
  });

  it('derives the same answer from expires_at when the flag is absent', () => {
    const tokens = [
      ...Array.from({ length: 12 }, () => token(undefined, FUTURE)),
      ...Array.from({ length: 8 }, () => token(undefined, PAST)),
    ];
    expect(isAtTokenLimit(tokens, 20, NOW)).toBe(false);
  });
});
