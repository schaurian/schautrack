package handler

import (
	"context"
	"os"
	"testing"
	"time"

	"schautrack/internal/database"
)

// TestSavedFoodVisibleToPredicate is the security test for quick-add sharing.
//
// The predicate decides whose saved foods a caller can read and track, so the
// interesting cases are the ones that must be REFUSED. account_links keeps one
// row per link with two direction-specific share maps, and reading the wrong
// branch turns "does the owner share with me" into "do I share with them" —
// which exposes foods the owner never offered.
//
// That inversion is invisible to a symmetric fixture, because with both
// directions enabled every assertion still passes. Hence the
// only-the-other-direction case below: it is the one that fails on a flipped
// CASE, and the reason this test exists at all.
func TestSavedFoodVisibleToPredicate(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	emails := []string{
		"sf-share-owner@handler.test",
		"sf-share-viewer@handler.test",
		"sf-share-stranger@handler.test",
	}
	cleanup := func() {
		for _, e := range emails {
			pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, e)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	ids := make(map[string]int, len(emails))
	for _, e := range emails {
		var id int
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (email, password_hash, email_verified)
			 VALUES ($1, 'x', true) RETURNING id`, e).Scan(&id); err != nil {
			t.Fatalf("seeding %s: %v", e, err)
		}
		ids[e] = id
	}
	owner, viewer, stranger := ids[emails[0]], ids[emails[1]], ids[emails[2]]

	var foodID int
	if err := pool.QueryRow(ctx,
		`INSERT INTO saved_foods (user_id, name, amount) VALUES ($1, 'Shared Oats', 300) RETURNING id`,
		owner).Scan(&foodID); err != nil {
		t.Fatalf("seeding the food: %v", err)
	}

	// visible runs the real predicate the handlers use, so the test cannot
	// drift from the thing it is guarding.
	visible := func(t *testing.T, caller int) bool {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM saved_foods WHERE id = $2 AND `+savedFoodVisibleTo,
			caller, foodID).Scan(&n); err != nil {
			t.Fatalf("predicate query: %v", err)
		}
		return n == 1
	}

	link := func(t *testing.T, requester, target int, requesterShares, targetShares string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `DELETE FROM account_links`); err != nil {
			t.Fatalf("clearing links: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO account_links (requester_id, target_id, status, requester_shares, target_shares)
			VALUES ($1, $2, 'accepted', $3::jsonb, $4::jsonb)`,
			requester, target, requesterShares, targetShares); err != nil {
			t.Fatalf("seeding the link: %v", err)
		}
	}

	const on = `{"savedfoods": true}`
	const off = `{"savedfoods": false}`

	t.Run("the owner always sees their own food", func(t *testing.T) {
		link(t, owner, viewer, off, off)
		if !visible(t, owner) {
			t.Error("owner cannot see their own saved food")
		}
	})

	t.Run("shared toward the viewer is visible", func(t *testing.T) {
		link(t, owner, viewer, on, off)
		if !visible(t, viewer) {
			t.Error("viewer cannot see a food the owner shares with them")
		}
	})

	t.Run("shared toward the viewer is visible with the link stored the other way round", func(t *testing.T) {
		// Same intent, opposite row orientation: the owner is now the target,
		// so the share lives in target_shares. Both branches of the CASE have
		// to be right, not just the one the first fixture happened to use.
		link(t, viewer, owner, off, on)
		if !visible(t, viewer) {
			t.Error("viewer cannot see a shared food when the owner is the link target")
		}
	})

	t.Run("sharing the OTHER way does not expose the owner's food", func(t *testing.T) {
		// The viewer shares with the owner; the owner shares nothing. This is
		// the inversion case: a flipped CASE reads the viewer's own share flag
		// and wrongly returns the owner's food.
		link(t, viewer, owner, on, off)
		if visible(t, viewer) {
			t.Error("viewer can see a food the owner does NOT share — the direction check is inverted")
		}
	})

	t.Run("an accepted link without the category shares nothing", func(t *testing.T) {
		link(t, owner, viewer, off, off)
		if visible(t, viewer) {
			t.Error("viewer can see a food over a link that does not enable savedfoods")
		}
	})

	t.Run("a pending link shares nothing", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `DELETE FROM account_links`); err != nil {
			t.Fatalf("clearing links: %v", err)
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO account_links (requester_id, target_id, status, requester_shares, target_shares)
			VALUES ($1, $2, 'pending', $3::jsonb, $3::jsonb)`, owner, viewer, on); err != nil {
			t.Fatalf("seeding the pending link: %v", err)
		}
		if visible(t, viewer) {
			t.Error("viewer can see a food over a link that has not been accepted")
		}
	})

	t.Run("an unlinked stranger sees nothing", func(t *testing.T) {
		link(t, owner, viewer, on, on)
		if visible(t, stranger) {
			t.Error("an unlinked user can see the owner's saved food")
		}
	})
}
