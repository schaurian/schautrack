package database

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
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

	var cached *SettingResult
	if ok {
		cached = &entry.result
	}
	result, cache := resolveSetting(value, err, cached)
	if cache {
		sc.set(key, result)
	}
	return result
}

// resolveSetting decides the SettingResult for a lookup and whether it is safe
// to cache, given the DB scan outcome and any (possibly stale) cached entry.
//
// A negative result is only cached when the row genuinely does not exist
// (pgx.ErrNoRows) or is SQL NULL. On any other error — most importantly a
// canceled request context, which a client can trigger at will by aborting its
// own request — we must NOT write {nil,"none"} to the cache for the full TTL,
// or a single aborted request would, for a minute, make enable_registration,
// the global ai_key, enable_legal, etc. read as unset for everyone. Instead we
// serve the stale cached value if we have one, or an uncached negative result.
func resolveSetting(value *string, err error, cached *SettingResult) (SettingResult, bool) {
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return SettingResult{Value: nil, Source: "none"}, true
		}
		if cached != nil {
			return *cached, false
		}
		return SettingResult{Value: nil, Source: "none"}, false
	}
	if value == nil {
		return SettingResult{Value: nil, Source: "none"}, true
	}
	return SettingResult{Value: value, Source: "db"}, true
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
