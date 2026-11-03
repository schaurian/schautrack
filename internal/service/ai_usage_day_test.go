package service

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"schautrack/internal/database"
)

// TestAIUsageIsKeyedByTheUsersDay checks that the AI quota counter lives on the
// calendar day the caller passes (the user's local date), not on the
// database's CURRENT_DATE. Far-future days are used so that a query still
// keyed on CURRENT_DATE cannot pass by coincidence.
func TestAIUsageIsKeyedByTheUsersDay(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}
	defer pool.Close()
	if err := database.InitSchemaWithRetry(ctx, pool, 3); err != nil {
		t.Fatalf("schema init failed: %v", err)
	}

	var userID int
	if err := pool.QueryRow(ctx,
		"INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id",
		fmt.Sprintf("ai-day-%d@example.com", time.Now().UnixNano()),
	).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	defer pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", userID)

	const day, nextDay = "2031-01-01", "2031-01-02"
	for want := 1; want <= 2; want++ {
		got, err := ReserveAIUsage(ctx, pool, userID, day)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("ReserveAIUsage #%d = %d, want %d", want, got, want)
		}
	}
	if got, _ := GetAIUsageToday(ctx, pool, userID, day); got != 2 {
		t.Errorf("usage on %s = %d, want 2", day, got)
	}
	// The user's next day starts from zero, whatever the database's date is.
	if got, _ := GetAIUsageToday(ctx, pool, userID, nextDay); got != 0 {
		t.Errorf("usage on %s = %d, want 0", nextDay, got)
	}
	// A release hands back the slot on the day it was reserved — even when
	// the request finished after midnight.
	ReleaseAIUsage(ctx, pool, userID, day)
	if got, _ := GetAIUsageToday(ctx, pool, userID, day); got != 1 {
		t.Errorf("after release, usage on %s = %d, want 1", day, got)
	}
}
