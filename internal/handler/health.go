package handler

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgxpool"
)

var shuttingDown atomic.Bool

func MarkShuttingDown() {
	shuttingDown.Store(true)
}

func Health(pool *pgxpool.Pool, buildVersion string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if shuttingDown.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{
				"app":     "schautrack",
				"status":  "shutting_down",
				"version": buildVersion,
			})
			return
		}

		err := pool.Ping(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{
				"app":     "schautrack",
				"status":  "error",
				"version": buildVersion,
			})
			return
		}

		stat := pool.Stat()
		json.NewEncoder(w).Encode(map[string]any{
			"app":     "schautrack",
			"status":  "ok",
			"version": buildVersion,
			"pool": map[string]any{
				"totalCount":   stat.TotalConns(),
				"idleCount":    stat.IdleConns(),
				"waitingCount": stat.EmptyAcquireCount(),
			},
		})
	}
}
