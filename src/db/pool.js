const { Pool, types } = require('pg');

// Return DATE columns as plain 'YYYY-MM-DD' strings instead of Date objects.
// The default pg parser creates dates at midnight in the *local* timezone,
// so .toISOString().slice(0,10) shifts the date by -1 day on UTC+ servers.
types.setTypeParser(1082, (val) => val);

// Validate required environment variables
if (!process.env.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL environment variable is required');
  process.exit(1);
}

const pool = new Pool({ 
  connectionString: process.env.DATABASE_URL,
  max: 20, // maximum pool size
  min: 2,  // minimum pool size  
  idleTimeoutMillis: 30000, // 30 seconds
  connectionTimeoutMillis: 10000, // 10 seconds
});

// Handle pool-level errors to prevent unhandled 'error' crashes
pool.on('error', (err) => {
  console.error('Unexpected PG pool error (connection lost?):', err.message);
  // Don't exit — the pool will automatically reconnect on next query
});

// Admin settings cache with per-key TTL
const settingsCache = new Map(); // Map<key, { result, timestamp }>
const SETTINGS_CACHE_TTL = 60000; // 1 minute

const getEffectiveSetting = async (key, envValue) => {
  if (envValue !== undefined && envValue !== null && envValue !== '') {
    return { value: envValue, source: 'env' };
  }

  const now = Date.now();
  const cached = settingsCache.get(key);
  if (cached && (now - cached.timestamp) < SETTINGS_CACHE_TTL) {
    return cached.result;
  }

  try {
    const { rows } = await pool.query('SELECT value FROM admin_settings WHERE key = $1', [key]);
    const result = rows.length > 0 && rows[0].value !== null
      ? { value: rows[0].value, source: 'db' }
      : { value: null, source: 'none' };
    settingsCache.set(key, { result, timestamp: now });
    return result;
  } catch (err) {
    console.error('Failed to get admin setting', key, err);
    return { value: null, source: 'none' };
  }
};

// Helper to invalidate settings cache (call after admin updates)
const invalidateSettingsCache = () => {
  settingsCache.clear();
};

const setAdminSetting = async (key, value) => {
  await pool.query(`
    INSERT INTO admin_settings (key, value, updated_at)
    VALUES ($1, $2, NOW())
    ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
  `, [key, value]);
  
  // Invalidate cache after updating settings
  invalidateSettingsCache();
};

module.exports = {
  pool,
  getEffectiveSetting,
  invalidateSettingsCache,
  setAdminSetting
};