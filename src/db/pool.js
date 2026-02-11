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

// Admin settings cache with TTL
let settingsCache = new Map();
let settingsCacheTime = 0;
const SETTINGS_CACHE_TTL = 60000; // 1 minute

const getEffectiveSetting = async (key, envValue) => {
  if (envValue !== undefined && envValue !== null && envValue !== '') {
    return { value: envValue, source: 'env' };
  }

  const now = Date.now();
  
  // Return cached value if still fresh
  if (settingsCache.has(key) && (now - settingsCacheTime) < SETTINGS_CACHE_TTL) {
    return settingsCache.get(key);
  }

  try {
    const result = await pool.query('SELECT value FROM admin_settings WHERE key = $1', [key]);
    let settingResult;
    if (result.rows.length > 0 && result.rows[0].value !== null) {
      settingResult = { value: result.rows[0].value, source: 'db' };
    } else {
      settingResult = { value: null, source: 'none' };
    }
    
    // Cache the result
    settingsCache.set(key, settingResult);
    settingsCacheTime = now;
    
    return settingResult;
  } catch (err) {
    console.error('Failed to get admin setting', key, err);
    return { value: null, source: 'none' };
  }
};

// Helper to invalidate settings cache (call after admin updates)
const invalidateSettingsCache = () => {
  settingsCache.clear();
  settingsCacheTime = 0;
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