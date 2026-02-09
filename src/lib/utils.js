const KG_TO_LB = 2.20462;

const toInt = (value) => {
  const num = parseInt(value, 10);
  return Number.isNaN(num) ? null : num;
};

const toIsoDate = (date) => date.toISOString().slice(0, 10);

const formatDateInTz = (date, timeZone) => {
  try {
    return new Intl.DateTimeFormat('en-CA', {
      timeZone: timeZone || 'UTC',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).format(date);
  } catch (err) {
    return toIsoDate(date);
  }
};

const formatTimeInTz = (date, timeZone) => {
  try {
    return new Intl.DateTimeFormat('en-GB', {
      timeZone: timeZone || 'UTC',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).format(date);
  } catch (err) {
    return date.toISOString().slice(11, 16);
  }
};

const kgToLbs = (kg) => (typeof kg === 'number' ? Math.round(kg * KG_TO_LB * 10) / 10 : null);

const lbsToKg = (lbs) => {
  const num = parseFloat(lbs);
  if (Number.isNaN(num) || num <= 0) return null;
  return Math.round((num / KG_TO_LB) * 100) / 100;
};

const parseCookies = (header) => {
  if (!header) return {};
  return header.split(';').reduce((acc, part) => {
    const [rawKey, ...rest] = part.split('=');
    const key = rawKey && rawKey.trim();
    if (!key) return acc;
    const value = rest.join('=').trim();
    try {
      acc[key] = decodeURIComponent(value);
    } catch (e) {
      acc[key] = value;
    }
    return acc;
  }, {});
};

const getClientTimezone = (req) => {
  const fromHeader = (req.headers['x-timezone'] || req.headers['x-tz'] || '').trim();
  if (fromHeader) return fromHeader.slice(0, 100);
  const cookies = parseCookies(req.headers.cookie);
  const fromCookie = (cookies.timezone || '').trim();
  if (fromCookie) return fromCookie.slice(0, 100);
  return null;
};

const rememberClientTimezone = (req, res) => {
  const tz = getClientTimezone(req);
  if (tz) {
    // Persist for future requests; express sets cookies without extra middleware.
    res.cookie('timezone', tz, { sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 365 });
  }
  return tz;
};

// Get the effective timezone for a user
const getUserTimezone = (req, res) => {
  const user = req.currentUser;
  if (user) {
    // Always use the user's saved timezone from database
    return user.timezone || 'UTC';
  }
  // For non-authenticated users, try to detect from client
  return getClientTimezone(req) || 'UTC';
};

// XML escape helper
const escapeXml = (unsafe) => {
  return unsafe.replace(/[<>&'"]/g, (c) => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '\'': return '&apos;';
      case '"': return '&quot;';
    }
  });
};

// Helper to generate text SVG
const textToSvg = (text, color = '#e5e7eb') => {
  if (!text) return '';
  const lines = String(text).split(/\\n|\n/);
  const fontSize = 16;
  const lineHeight = 24;
  const height = lines.length * lineHeight;
  // Estimate width: avg char width approx 9px at 16px font
  const maxLen = Math.max(...lines.map(l => l.length));
  const width = Math.max(maxLen * 10, 100); 
  
  const svgContent = lines.map((line, i) => 
    `<text x="0" y="${(i + 1) * lineHeight - 6}" fill="${color}" font-family="sans-serif" font-weight="500" font-size="${fontSize}">${escapeXml(line)}</text>`
  ).join('');

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
    <style>text { font-family: "Space Grotesk", sans-serif; }</style>
    ${svgContent}
  </svg>`;
};

const parseWeight = (input) => {
  if (input === undefined || input === null) {
    return { ok: false, value: null };
  }
  const normalized = String(input)
    .replace(',', '.')
    .replace(/[^0-9.+-]/g, '')
    .trim();
  if (!normalized || normalized.length > 12) {
    return { ok: false, value: null };
  }
  const value = Number.parseFloat(normalized);
  if (!Number.isFinite(value) || value <= 0 || value > 1500) {
    return { ok: false, value: null };
  }
  return { ok: true, value: Math.round(value * 10) / 10 };
};

module.exports = {
  KG_TO_LB,
  toInt,
  toIsoDate,
  formatDateInTz,
  formatTimeInTz,
  kgToLbs,
  lbsToKg,
  parseCookies,
  getClientTimezone,
  rememberClientTimezone,
  getUserTimezone,
  escapeXml,
  textToSvg,
  parseWeight
};