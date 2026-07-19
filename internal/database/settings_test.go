package database

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
)

func strPtr(s string) *string { return &s }

func TestResolveSetting(t *testing.T) {
	staleVal := strPtr("stale-db-value")
	stale := &SettingResult{Value: staleVal, Source: "db"}

	tests := []struct {
		name       string
		value      *string
		err        error
		cached     *SettingResult
		wantValue  *string
		wantSource string
		wantCache  bool
	}{
		{
			name:       "no rows caches negative",
			err:        pgx.ErrNoRows,
			wantSource: "none",
			wantCache:  true,
		},
		{
			name:       "wrapped no rows caches negative",
			err:        fmt.Errorf("query admin_settings: %w", pgx.ErrNoRows),
			wantSource: "none",
			wantCache:  true,
		},
		{
			// The core fix: a transient error (e.g. canceled request context)
			// must NOT poison the cache; serve the stale entry instead.
			name:       "transient error with cache serves stale, no write",
			err:        context.Canceled,
			cached:     stale,
			wantValue:  staleVal,
			wantSource: "db",
			wantCache:  false,
		},
		{
			name:       "transient error without cache returns none, no write",
			err:        context.Canceled,
			wantSource: "none",
			wantCache:  false,
		},
		{
			name:       "value present caches db result",
			value:      strPtr("real"),
			wantValue:  strPtr("real"),
			wantSource: "db",
			wantCache:  true,
		},
		{
			name:       "sql null value caches negative",
			value:      nil,
			err:        nil,
			wantSource: "none",
			wantCache:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, cache := resolveSetting(tt.value, tt.err, tt.cached)
			if cache != tt.wantCache {
				t.Errorf("cache = %v, want %v", cache, tt.wantCache)
			}
			if got.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", got.Source, tt.wantSource)
			}
			if (got.Value == nil) != (tt.wantValue == nil) {
				t.Fatalf("Value nil-ness = %v, want %v", got.Value == nil, tt.wantValue == nil)
			}
			if got.Value != nil && *got.Value != *tt.wantValue {
				t.Errorf("Value = %q, want %q", *got.Value, *tt.wantValue)
			}
		})
	}
}
