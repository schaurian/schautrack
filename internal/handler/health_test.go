package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// unreachablePool builds a pool pointing at a TCP port nothing is listening
// on. Grabbing a real ephemeral port and closing it immediately (rather than
// guessing a fixed one) means the target is guaranteed free and connection
// attempts fail fast with "connection refused" instead of a slow timeout.
// pgxpool.NewWithConfig never dials on its own — the pool is created lazily —
// so building it here does no I/O; only a later Ping (or query) touches the
// network.
func unreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	dsn := fmt.Sprintf("postgres://user:pass@%s/db?sslmode=disable&connect_timeout=2", addr)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestLivezReturnsOK is the baseline: the liveness probe must succeed with no
// setup at all — no pool, no session, no config.
func TestLivezReturnsOK(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/livez", nil)
	w := httptest.NewRecorder()
	Livez(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// TestLivezIgnoresDatabaseOutage is the entire point of this endpoint: a dead
// database must never fail liveness. It proves this by first confirming
// Health — the DB-aware readiness endpoint — really does fail against an
// unreachable database (otherwise the test would prove nothing), then showing
// Livez still reports healthy against that same outage.
func TestLivezIgnoresDatabaseOutage(t *testing.T) {
	pool := unreachablePool(t)

	h := Health(pool, "test")
	hr := httptest.NewRequest("GET", "/api/health", nil)
	hw := httptest.NewRecorder()
	h(hw, hr)
	if hw.Code != http.StatusServiceUnavailable {
		t.Fatalf("Health status = %d, want 503 (database must be unreachable for this test to prove anything)", hw.Code)
	}

	lr := httptest.NewRequest("GET", "/api/livez", nil)
	lw := httptest.NewRecorder()
	Livez(lw, lr)
	if lw.Code != http.StatusOK {
		t.Errorf("Livez status = %d, want 200 — liveness must not depend on the database, and Health above just proved it is down", lw.Code)
	}
}

func TestHealthEndpointShuttingDown(t *testing.T) {
	// Mark shutting down
	shuttingDown.Store(true)
	defer shuttingDown.Store(false)

	h := Health(nil, "test")
	r := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "shutting_down" {
		t.Errorf("status = %v, want shutting_down", resp["status"])
	}
}

func TestHealthEndpointShuttingDown_IncludesVersionAndApp(t *testing.T) {
	shuttingDown.Store(true)
	defer shuttingDown.Store(false)

	h := Health(nil, "v1.0.0")
	r := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", w.Code)
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["version"] != "v1.0.0" {
		t.Errorf("version = %v, want v1.0.0", resp["version"])
	}
	if resp["app"] != "schautrack" {
		t.Errorf("app = %v, want schautrack", resp["app"])
	}
}
