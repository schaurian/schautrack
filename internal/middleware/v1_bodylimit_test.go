// This file is in the external test package because it imports
// internal/handler to mount the real /api/v1 router, and internal/handler
// imports internal/middleware — an in-package test file would be an import
// cycle.
package middleware_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/apierr"
	"schautrack/internal/database"
	"schautrack/internal/handler"
	"schautrack/internal/middleware"
	"schautrack/internal/service"
)

// TestV1BodyLimitBeatsTheGlobalLimit covers the interaction between the two
// request caps this application has.
//
// cmd/server/main.go mounts middleware.MaxBodySize(15 << 20) globally, sized
// for photo uploads and account imports on the legacy surface. handler's
// decodeV1 wraps the body a second time at maxV1Body (1 MB), because nothing
// on the public API takes a payload anywhere near 15 MB.
//
// A 5 MB request to a v1 route therefore sits between the two limits, and the
// tighter one has to win — with the v1 surface's error contract (RFC 9457
// problem+json, 413), not a bare net/http rejection. Getting this wrong in
// either direction is invisible from a unit test of either middleware alone:
// the global cap would silently accept 5 MB, and the v1 cap can only be
// reached through the real router.
//
// Needs a database: /api/v1 authenticates with a real personal access token,
// and RequireAPIToken runs before any body is read.
func TestV1BodyLimitBeatsTheGlobalLimit(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	if err := database.InitSchemaWithRetry(ctx, pool, 3); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	email := fmt.Sprintf("v1-bodylimit-%d@middleware.test", time.Now().UnixNano())
	var userID int
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, email_verified) VALUES ($1, 'x', true) RETURNING id`,
		email).Scan(&userID); err != nil {
		t.Fatalf("seeding the user failed: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	})

	_, rawToken, err := service.CreateAPIToken(ctx, pool, userID, "body limit test",
		[]string{service.ScopeEntriesWrite}, nil)
	if err != nil {
		t.Fatalf("minting an API token failed: %v", err)
	}

	// The same two layers as production: the global cap outside, the real v1
	// router (which applies maxV1Body inside decodeV1) within.
	v1 := &handler.V1Handler{Pool: pool}
	root := chi.NewRouter()
	root.Use(middleware.MaxBodySize(15 << 20))
	root.Mount("/api/v1", v1.MountAPIV1(pool))

	srv := httptest.NewServer(root)
	defer srv.Close()

	post := func(t *testing.T, body []byte) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/entries", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("building the request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+rawToken)

		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("the request produced a transport error instead of an HTTP response: %v", err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	decodeProblem := func(t *testing.T, resp *http.Response) apierr.Problem {
		t.Helper()
		var p apierr.Problem
		if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
			t.Fatalf("response body is not a problem document: %v", err)
		}
		return p
	}

	// Control: a well-formed but rejected small body proves the route is
	// reachable with this token, so a 413 below is really the size check and
	// not a mis-wired test.
	t.Run("control: a small body reaches the handler", func(t *testing.T) {
		resp := post(t, []byte(`{"totally_unknown_field": 1}`))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for an unknown field (the route must be reachable)", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != apierr.ContentType {
			t.Errorf("Content-Type = %q, want %q", ct, apierr.ContentType)
		}
	})

	// 5 MB: under the 15 MB global cap, far over the 1 MB v1 cap.
	t.Run("5 MB hits the v1 limit, not the global one", func(t *testing.T) {
		body := append([]byte(`{"description":"`), bytes.Repeat([]byte("a"), 5<<20)...)
		body = append(body, []byte(`","calories":100}`)...)

		resp := post(t, body)
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413 — a 5 MB body slipped past the 1 MB v1 cap", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != apierr.ContentType {
			t.Errorf("Content-Type = %q, want %q — the v1 surface must answer in problem+json even here",
				ct, apierr.ContentType)
		}

		p := decodeProblem(t, resp)
		if !strings.HasSuffix(p.Type, "/body-too-large") {
			t.Errorf("problem type = %q, want the body-too-large type", p.Type)
		}
		if p.Status != http.StatusRequestEntityTooLarge {
			t.Errorf("problem status field = %d, want 413", p.Status)
		}
		if !strings.Contains(p.Detail, "1048576") {
			t.Errorf("detail = %q; it should name the 1 MB v1 limit so a caller knows which cap it hit "+
				"(quoting the 15 MB global limit here would be actively misleading)", p.Detail)
		}
	})

	// Over the global cap too. The v1 reader is the inner one, so it still
	// trips first and the caller still gets a problem document rather than
	// net/http's bare "request body too large".
	t.Run("20 MB still produces a v1 problem document", func(t *testing.T) {
		body := append([]byte(`{"description":"`), bytes.Repeat([]byte("a"), 20<<20)...)
		body = append(body, []byte(`","calories":100}`)...)

		resp := post(t, body)
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != apierr.ContentType {
			t.Errorf("Content-Type = %q, want %q", ct, apierr.ContentType)
		}
	})
}
