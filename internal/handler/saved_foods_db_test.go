package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/sse"
)

// TestSavedFoodUpdateNullClearsColumns is the #388 regression test, and it
// deliberately goes all the way to the column.
//
// The bug was never visible in the response alone: POST {"amount": null} came
// back 400 "No updates provided" *and* left the row untouched, so an assertion
// on the status code would have caught it but an assertion on the returned
// savedFood would not have — the handler never reached the UPDATE. Reading the
// column back after every call is what pins the fix: for a nullable column,
// "the endpoint returned 200" and "the value is gone" are different claims.
//
// Every nullable field on the endpoint is exercised through the same three
// states, because the UI edits them from one form and a user does not know
// which of them the server treats specially:
//
//	key absent               -> leave the column alone
//	key present, JSON null   -> clear the column
//	key present, with value  -> set the column
//
// name is excluded on purpose: saved_foods.name is NOT NULL, so it has no
// clear state, and #385 settled a null there as a 400.
//
// Skipped unless TEST_DATABASE_URL is set, matching internal/database's
// integration tests and TestOnboardingCompleteKeepsFirstTimestamp.
func TestSavedFoodUpdateNullClearsColumns(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// database.NewPool, not pgxpool.New: the app registers a codec that scans
	// DATE columns straight into string, and a bare pool does not get it (see
	// internal/database's TestNoTestBuildsABarePool).
	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	const email = "saved-food-clear@handler.test"
	cleanup := func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, email) }
	cleanup()
	t.Cleanup(cleanup)

	var userID int
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, email_verified)
		 VALUES ($1, 'x', true) RETURNING id`, email).Scan(&userID); err != nil {
		t.Fatalf("seeding the user failed: %v", err)
	}

	h := &SavedFoodsHandler{Pool: pool, Broker: sse.NewBroker(pool)}

	// seed re-creates the row in a known state before each subtest so the
	// subtests cannot influence one another through the shared table.
	seed := func(t *testing.T) int {
		t.Helper()
		if _, err := pool.Exec(ctx, `DELETE FROM saved_foods WHERE user_id = $1`, userID); err != nil {
			t.Fatalf("clearing saved_foods: %v", err)
		}
		var id int
		if err := pool.QueryRow(ctx, `
			INSERT INTO saved_foods (user_id, name, emoji, amount, protein_g, carbs_g, fat_g, fiber_g, sugar_g)
			VALUES ($1, 'Pizza', '🍕', 500, 30, 60, 20, 5, 8)
			RETURNING id`, userID).Scan(&id); err != nil {
			t.Fatalf("seeding the saved food failed: %v", err)
		}
		return id
	}

	// column reads the nullable int column back, exactly as Postgres holds it.
	column := func(t *testing.T, id int, col string) *int {
		t.Helper()
		var v *int
		if err := pool.QueryRow(ctx,
			`SELECT `+col+` FROM saved_foods WHERE id = $1`, id).Scan(&v); err != nil {
			t.Fatalf("reading %s back: %v", col, err)
		}
		return v
	}

	textColumn := func(t *testing.T, id int, col string) *string {
		t.Helper()
		var v *string
		if err := pool.QueryRow(ctx,
			`SELECT `+col+` FROM saved_foods WHERE id = $1`, id).Scan(&v); err != nil {
			t.Fatalf("reading %s back: %v", col, err)
		}
		return v
	}

	update := func(t *testing.T, id int, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/saved-foods/"+strconv.Itoa(id)+"/update",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", strconv.Itoa(id))
		c := context.WithValue(ctx, chi.RouteCtxKey, rctx)
		req = req.WithContext(middleware.WithTestUser(c, &model.User{ID: userID, Email: email}))
		rec := httptest.NewRecorder()
		h.Update(rec, req)
		return rec
	}

	describe := func(v *int) string {
		if v == nil {
			return "NULL"
		}
		return strconv.Itoa(*v)
	}
	describeText := func(v *string) string {
		if v == nil {
			return "NULL"
		}
		return *v
	}

	t.Run("null clears the calories", func(t *testing.T) {
		id := seed(t)
		before := column(t, id, "amount")
		if before == nil || *before != 500 {
			t.Fatalf("seed: amount = %s, want 500", describe(before))
		}

		rec := update(t, id, `{"amount": null}`)
		after := column(t, id, "amount")
		t.Logf("amount before = %s | POST {\"amount\": null} -> %d %s | amount after = %s",
			describe(before), rec.Code, strings.TrimSpace(rec.Body.String()), describe(after))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		if after != nil {
			t.Fatalf("amount = %d after clearing; the column was not written", *after)
		}

		// The response must agree with the column, or the UI re-renders the
		// stale value it just cleared.
		var resp struct {
			OK        bool `json:"ok"`
			SavedFood struct {
				Amount *int `json:"amount"`
			} `json:"savedFood"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("response was not JSON: %v (%s)", err, rec.Body.String())
		}
		if !resp.OK || resp.SavedFood.Amount != nil {
			t.Errorf("response savedFood.amount = %v, want null", resp.SavedFood.Amount)
		}
	})

	t.Run("an absent amount leaves the calories alone", func(t *testing.T) {
		id := seed(t)
		rec := update(t, id, `{"emoji": "🥑"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		after := column(t, id, "amount")
		if after == nil || *after != 500 {
			t.Fatalf("amount = %s, want the untouched 500", describe(after))
		}
	})

	t.Run("a value sets the calories", func(t *testing.T) {
		id := seed(t)
		if rec := update(t, id, `{"amount": 750}`); rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		after := column(t, id, "amount")
		if after == nil || *after != 750 {
			t.Fatalf("amount = %s, want 750", describe(after))
		}
	})

	t.Run("an empty string still clears the calories", func(t *testing.T) {
		id := seed(t)
		if rec := update(t, id, `{"amount": ""}`); rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		if after := column(t, id, "amount"); after != nil {
			t.Fatalf("amount = %d, want NULL", *after)
		}
	})

	t.Run("an unparseable amount is still a 400 and writes nothing", func(t *testing.T) {
		id := seed(t)
		rec := update(t, id, `{"amount": "abc"}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
		}
		after := column(t, id, "amount")
		if after == nil || *after != 500 {
			t.Fatalf("amount = %s, want the untouched 500", describe(after))
		}
	})

	t.Run("null clears the emoji", func(t *testing.T) {
		id := seed(t)
		before := textColumn(t, id, "emoji")
		rec := update(t, id, `{"emoji": null}`)
		after := textColumn(t, id, "emoji")
		t.Logf("emoji before = %s | POST {\"emoji\": null} -> %d | emoji after = %s",
			describeText(before), rec.Code, describeText(after))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
		}
		if after != nil {
			t.Fatalf("emoji = %q, want NULL", *after)
		}
	})

	for _, macro := range []string{"protein", "carbs", "fat", "fiber", "sugar"} {
		t.Run("null clears "+macro, func(t *testing.T) {
			id := seed(t)
			col := macro + "_g"
			before := column(t, id, col)
			rec := update(t, id, `{"`+col+`": null}`)
			after := column(t, id, col)
			t.Logf("%s before = %s | POST {\"%s\": null} -> %d | %s after = %s",
				col, describe(before), col, rec.Code, col, describe(after))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
			}
			if after != nil {
				t.Fatalf("%s = %d, want NULL", col, *after)
			}
		})
	}

	t.Run("an empty body is still No updates provided", func(t *testing.T) {
		id := seed(t)
		rec := update(t, id, `{}`)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
		}
		after := column(t, id, "amount")
		if after == nil || *after != 500 {
			t.Fatalf("amount = %s, want the untouched 500", describe(after))
		}
	})
}
