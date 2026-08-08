package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
)

// savedFoodsTestPool opens the integration pool and applies migrations, or
// skips. Matches internal/database's convention: no TEST_DATABASE_URL, no run.
func savedFoodsTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return ctx, pool
}

// seedSavedFoodsUser creates a throwaway account and returns its id. The
// account (and its foods, via ON DELETE CASCADE) is removed afterwards.
func seedSavedFoodsUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) int {
	t.Helper()
	cleanup := func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, email) }
	cleanup()
	t.Cleanup(cleanup)

	var id int
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, email_verified)
		 VALUES ($1, 'x', true) RETURNING id`, email).Scan(&id); err != nil {
		t.Fatalf("seeding the user failed: %v", err)
	}
	return id
}

// listSavedFoodsV1 calls the handler as the given user and returns the decoded
// envelope plus the raw body, so a test can assert on absent JSON keys.
func listSavedFoodsV1(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID int, query string) (v1List[v1SavedFood], map[string]json.RawMessage) {
	t.Helper()
	h := &V1Handler{Pool: pool}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/saved-foods"+query, nil)
	req = req.WithContext(middleware.WithTestUser(ctx, &model.User{ID: userID}))
	rec := httptest.NewRecorder()
	h.ListSavedFoodsV1(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/saved-foods%s: status = %d, want 200 (body %s)", query, rec.Code, rec.Body.String())
	}
	var page v1List[v1SavedFood]
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decoding the list failed: %v (body %s)", err, rec.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decoding the raw envelope failed: %v", err)
	}
	return page, raw
}

// TestListSavedFoodsV1ReturnsEveryFood is the regression test for #298.
//
// The endpoint used to apply `LIMIT $2` with a 50-row default while
// has_more/next_cursor stayed omitempty-absent, so an account with more than
// 50 saved foods received a silently truncated list that was indistinguishable
// from a complete one. A syncing client read the shortfall as deletions.
//
// 60 foods is deliberately just over the old 50-row default and well under the
// 200-food account cap: the whole set must come back, and the response must
// still carry no pagination fields, because there is nothing left to paginate.
func TestListSavedFoodsV1ReturnsEveryFood(t *testing.T) {
	ctx, pool := savedFoodsTestPool(t)
	userID := seedSavedFoodsUser(t, ctx, pool, "v1-saved-foods-page@handler.test")

	const want = 60 // > defaultPageSize (50), < MaxSavedFoods (200)
	for i := range want {
		if _, err := pool.Exec(ctx,
			`INSERT INTO saved_foods (user_id, name, amount) VALUES ($1, $2, $3)`,
			userID, fmt.Sprintf("food-%03d", i), 100+i); err != nil {
			t.Fatalf("seeding food %d failed: %v", i, err)
		}
	}

	page, raw := listSavedFoodsV1(t, ctx, pool, userID, "")
	if got := len(page.Data); got != want {
		t.Errorf("returned %d of %d saved foods; a partial list is indistinguishable from a complete one", got, want)
	}
	if _, ok := raw["has_more"]; ok {
		t.Errorf("response carries has_more = %s; an unpaginated complete list must not claim pagination", raw["has_more"])
	}
	if _, ok := raw["next_cursor"]; ok {
		t.Errorf("response carries next_cursor = %s; there is no next page to point at", raw["next_cursor"])
	}

	// `limit` must no longer be able to drop rows. Ignoring it can only ever
	// return more than asked for; it can never lose data.
	page, _ = listSavedFoodsV1(t, ctx, pool, userID, "?limit=10")
	if got := len(page.Data); got != want {
		t.Errorf("?limit=10 returned %d of %d saved foods; limit must not silently truncate", got, want)
	}

	// A limit that no longer parses must not start failing the request either,
	// now that the parameter is not read at all.
	page, _ = listSavedFoodsV1(t, ctx, pool, userID, "?limit=not-a-number")
	if got := len(page.Data); got != want {
		t.Errorf("?limit=not-a-number returned %d of %d saved foods", got, want)
	}
}

// TestListSavedFoodsV1TieBreakMatchesLegacy pins the two saved-food list
// endpoints to one order.
//
// v1 ended its ORDER BY with `id` ascending while the app's /api/saved-foods
// used `id DESC`, so foods tied on use_count and last_used_at — every food
// that has never been tracked, i.e. all of them right after you create a
// few — came back reversed between the two surfaces, contradicting v1's
// "ranked the way the app ranks them".
func TestListSavedFoodsV1TieBreakMatchesLegacy(t *testing.T) {
	ctx, pool := savedFoodsTestPool(t)
	userID := seedSavedFoodsUser(t, ctx, pool, "v1-saved-foods-order@handler.test")

	// A mix: several never-used foods (the tie that used to reverse), plus
	// rows that exercise the use_count and last_used_at keys ahead of it, and
	// a same-use_count pair split by last_used_at.
	now := time.Now().UTC()
	seed := []struct {
		name     string
		useCount int
		lastUsed *time.Time
	}{
		{"never-used-a", 0, nil},
		{"never-used-b", 0, nil},
		{"never-used-c", 0, nil},
		{"used-once", 1, ptrTime(now.Add(-72 * time.Hour))},
		{"used-twice-older", 2, ptrTime(now.Add(-48 * time.Hour))},
		{"used-twice-newer", 2, ptrTime(now.Add(-1 * time.Hour))},
		{"used-most", 9, ptrTime(now.Add(-240 * time.Hour))},
	}
	for _, s := range seed {
		if _, err := pool.Exec(ctx,
			`INSERT INTO saved_foods (user_id, name, use_count, last_used_at) VALUES ($1, $2, $3, $4)`,
			userID, s.name, s.useCount, s.lastUsed); err != nil {
			t.Fatalf("seeding %q failed: %v", s.name, err)
		}
	}

	page, _ := listSavedFoodsV1(t, ctx, pool, userID, "")
	v1IDs := make([]int, 0, len(page.Data))
	v1Names := make([]string, 0, len(page.Data))
	for _, f := range page.Data {
		v1IDs = append(v1IDs, f.ID)
		v1Names = append(v1Names, f.Name)
	}

	legacy := &SavedFoodsHandler{Pool: pool}
	req := httptest.NewRequest(http.MethodGet, "/api/saved-foods", nil)
	req = req.WithContext(middleware.WithTestUser(ctx, &model.User{ID: userID}))
	rec := httptest.NewRecorder()
	legacy.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/saved-foods: status = %d (body %s)", rec.Code, rec.Body.String())
	}
	var legacyBody struct {
		SavedFoods []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
		} `json:"savedFoods"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &legacyBody); err != nil {
		t.Fatalf("decoding the legacy list failed: %v", err)
	}
	legacyIDs := make([]int, 0, len(legacyBody.SavedFoods))
	legacyNames := make([]string, 0, len(legacyBody.SavedFoods))
	for _, f := range legacyBody.SavedFoods {
		legacyIDs = append(legacyIDs, f.ID)
		legacyNames = append(legacyNames, f.Name)
	}

	if len(v1IDs) != len(seed) || len(legacyIDs) != len(seed) {
		t.Fatalf("row counts differ: v1 %d, legacy %d, seeded %d", len(v1IDs), len(legacyIDs), len(seed))
	}
	for i := range v1IDs {
		if v1IDs[i] != legacyIDs[i] {
			t.Fatalf("ordering diverges at position %d:\n  v1     = %v\n  legacy = %v",
				i, v1Names, legacyNames)
		}
	}

	// Pin the ranking itself, so "they agree" cannot be satisfied by both
	// endpoints regressing together.
	wantOrder := []string{
		"used-most",        // highest use_count
		"used-twice-newer", // use_count 2, more recent
		"used-twice-older", // use_count 2, older
		"used-once",        // use_count 1
		"never-used-c",     // untouched, newest id first
		"never-used-b",     //
		"never-used-a",     //
	}
	for i, want := range wantOrder {
		if v1Names[i] != want {
			t.Fatalf("rank at position %d = %q, want %q (full order %v)", i, v1Names[i], want, v1Names)
		}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
