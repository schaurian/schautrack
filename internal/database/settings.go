package database

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type SettingResult struct {
	Value  *string
	Source string // "env", "db", "none"
}

type settingsCacheEntry struct {
	result    SettingResult
	timestamp time.Time
}

type SettingsCache struct {
	pool  *pgxpool.Pool
	mu    sync.RWMutex
	cache map[string]settingsCacheEntry
	ttl   time.Duration
}

func NewSettingsCache(pool *pgxpool.Pool) *SettingsCache {
	return &SettingsCache{
		pool:  pool,
		cache: make(map[string]settingsCacheEntry),
		ttl:   time.Minute,
	}
}

func (sc *SettingsCache) GetEffectiveSetting(ctx context.Context, key string, envValue string) SettingResult {
	if envValue != "" {
		return SettingResult{Value: &envValue, Source: "env"}
	}

	sc.mu.RLock()
	entry, ok := sc.cache[key]
	sc.mu.RUnlock()

	if ok && time.Since(entry.timestamp) < sc.ttl {
		return entry.result
	}

	var value *string
	err := sc.pool.QueryRow(ctx, "SELECT value FROM admin_settings WHERE key = $1", key).Scan(&value)
	if err != nil || value == nil {
		result := SettingResult{Value: nil, Source: "none"}
		sc.set(key, result)
		return result
	}

	result := SettingResult{Value: value, Source: "db"}
	sc.set(key, result)
	return result
}

func (sc *SettingsCache) SetAdminSetting(ctx context.Context, key string, value string) error {
	_, err := sc.pool.Exec(ctx, `
		INSERT INTO admin_settings (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
	`, key, value)
	if err != nil {
		return err
	}
	sc.Invalidate()
	return nil
}

func (sc *SettingsCache) Invalidate() {
	sc.mu.Lock()
	sc.cache = make(map[string]settingsCacheEntry)
	sc.mu.Unlock()
}

func (sc *SettingsCache) set(key string, result SettingResult) {
	sc.mu.Lock()
	sc.cache[key] = settingsCacheEntry{result: result, timestamp: time.Now()}
	sc.mu.Unlock()
}
