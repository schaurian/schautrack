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

// Livez handles GET /api/livez — the liveness probe. It answers only "is
// this process still able to serve HTTP", never "are my dependencies up":
// the handler takes no pool and touches no external resource, so it cannot
// fail because Postgres blipped. That distinction matters operationally —
// Health (readiness) pings the database and legitimately returns 503 when it
// can't reach it, which is correct for pulling a pod out of the Service. If
// the same check gated liveness, every replica would fail it simultaneously
// on a single DB hiccup and kubelet would restart all of them at once,
// turning a recoverable dependency outage into a cluster-wide crashloop.
// Deliberately allocation-light: no JSON encoding, just a status and a body.
func Livez(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
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
