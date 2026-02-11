const { Pool } = require('pg');

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