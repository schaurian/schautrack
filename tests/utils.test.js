const { describe, test, expect } = require('@jest/globals');
const {
  toInt,
  toIsoDate,
  formatDateInTz,
  formatTimeInTz,
  parseCookies,
  getClientTimezone,
  escapeXml,
  textToSvg,
} = require('../src/lib/utils');

describe('toInt', () => {
  test('parses valid integers', () => {
    expect(toInt('42')).toBe(42);
    expect(toInt('0')).toBe(0);
    expect(toInt('-5')).toBe(-5);
    expect(toInt(10)).toBe(10);
  });

  test('truncates floats', () => {
    expect(toInt('3.9')).toBe(3);
    expect(toInt(7.7)).toBe(7);
  });

  test('returns null for non-numeric input', () => {
    expect(toInt('abc')).toBe(null);
    expect(toInt('')).toBe(null);
    expect(toInt(null)).toBe(null);
    expect(toInt(undefined)).toBe(null);
    expect(toInt(NaN)).toBe(null);
  });
});

describe('toIsoDate', () => {
  test('formats date as YYYY-MM-DD', () => {
    expect(toIsoDate(new Date('2024-03-15T12:00:00Z'))).toBe('2024-03-15');
    expect(toIsoDate(new Date('2024-01-01T00:00:00Z'))).toBe('2024-01-01');
  });
});

describe('formatDateInTz', () => {
  test('formats date in given timezone', () => {
    const date = new Date('2024-06-15T23:30:00Z');
    // In UTC it's June 15, but in Tokyo (UTC+9) it's June 16
    expect(formatDateInTz(date, 'Asia/Tokyo')).toBe('2024-06-16');
    expect(formatDateInTz(date, 'UTC')).toBe('2024-06-15');
  });

  test('defaults to UTC for falsy timezone', () => {
    const date = new Date('2024-06-15T12:00:00Z');
    expect(formatDateInTz(date, '')).toBe('2024-06-15');
    expect(formatDateInTz(date, null)).toBe('2024-06-15');
  });

  test('falls back to ISO date for invalid timezone', () => {
    const date = new Date('2024-06-15T12:00:00Z');
    expect(formatDateInTz(date, 'Invalid/Zone')).toBe('2024-06-15');
  });
});

describe('formatTimeInTz', () => {
  test('formats time in given timezone (24h)', () => {
    const date = new Date('2024-06-15T14:30:00Z');
    expect(formatTimeInTz(date, 'UTC')).toBe('14:30');
  });

  test('converts to target timezone', () => {
    const date = new Date('2024-06-15T14:30:00Z');
    // UTC+9 = 23:30
    expect(formatTimeInTz(date, 'Asia/Tokyo')).toBe('23:30');
  });

  test('falls back for invalid timezone', () => {
    const date = new Date('2024-06-15T14:30:00Z');
    expect(formatTimeInTz(date, 'Invalid/Zone')).toBe('14:30');
  });
});

describe('parseCookies', () => {
  test('parses cookie header string', () => {
    expect(parseCookies('foo=bar; baz=qux')).toEqual({ foo: 'bar', baz: 'qux' });
  });

  test('handles URL-encoded values', () => {
    expect(parseCookies('name=hello%20world')).toEqual({ name: 'hello world' });
  });

  test('handles values with equals signs', () => {
    expect(parseCookies('token=abc=def=')).toEqual({ token: 'abc=def=' });
  });

  test('returns empty object for empty/null header', () => {
    expect(parseCookies('')).toEqual({});
    expect(parseCookies(null)).toEqual({});
    expect(parseCookies(undefined)).toEqual({});
  });
});

describe('getClientTimezone', () => {
  test('reads from x-timezone header', () => {
    const req = { headers: { 'x-timezone': 'America/New_York' } };
    expect(getClientTimezone(req)).toBe('America/New_York');
  });

  test('reads from x-tz header', () => {
    const req = { headers: { 'x-tz': 'Europe/Berlin' } };
    expect(getClientTimezone(req)).toBe('Europe/Berlin');
  });

  test('reads from cookie', () => {
    const req = { headers: { cookie: 'timezone=Asia/Tokyo' } };
    expect(getClientTimezone(req)).toBe('Asia/Tokyo');
  });

  test('prefers header over cookie', () => {
    const req = { headers: { 'x-timezone': 'UTC', cookie: 'timezone=Asia/Tokyo' } };
    expect(getClientTimezone(req)).toBe('UTC');
  });

  test('returns null when no timezone found', () => {
    const req = { headers: {} };
    expect(getClientTimezone(req)).toBe(null);
  });

  test('truncates long values to 100 chars', () => {
    const long = 'A'.repeat(200);
    const req = { headers: { 'x-timezone': long } };
    expect(getClientTimezone(req)).toHaveLength(100);
  });
});

describe('escapeXml', () => {
  test('escapes all special XML characters', () => {
    expect(escapeXml('<script>')).toBe('&lt;script&gt;');
    expect(escapeXml('a & b')).toBe('a &amp; b');
    expect(escapeXml("it's")).toBe('it&apos;s');
    expect(escapeXml('"quoted"')).toBe('&quot;quoted&quot;');
  });

  test('leaves safe strings unchanged', () => {
    expect(escapeXml('hello world')).toBe('hello world');
  });
});

describe('textToSvg', () => {
  test('returns empty string for falsy input', () => {
    expect(textToSvg('')).toBe('');
    expect(textToSvg(null)).toBe('');
    expect(textToSvg(undefined)).toBe('');
  });

  test('generates valid SVG with text content', () => {
    const svg = textToSvg('Hello');
    expect(svg).toContain('<svg');
    expect(svg).toContain('</svg>');
    expect(svg).toContain('Hello');
  });

  test('handles multi-line text with literal \\n', () => {
    const svg = textToSvg('Line1\\nLine2');
    expect(svg).toContain('Line1');
    expect(svg).toContain('Line2');
    // Should have two <text> elements
    expect((svg.match(/<text /g) || []).length).toBe(2);
  });

  test('handles multi-line text with real newlines', () => {
    const svg = textToSvg('Line1\nLine2\nLine3');
    expect((svg.match(/<text /g) || []).length).toBe(3);
  });

  test('escapes XML in text content', () => {
    const svg = textToSvg('<script>alert(1)</script>');
    expect(svg).not.toContain('<script>');
    expect(svg).toContain('&lt;script&gt;');
  });

  test('uses custom color', () => {
    const svg = textToSvg('test', '#ff0000');
    expect(svg).toContain('fill="#ff0000"');
  });
});
