package service

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"schautrack/internal/database"
	"schautrack/internal/model"
)

// TestUpsertActiveGoalOneActiveInvariant exercises UpsertActiveGoal/GetActiveGoal
// against a real database, verifying that upserting a second goal abandons the
// first and that only one 'active' goal ever exists per user (the DB's partial
// unique index backstops this, but this test proves the service-level flow
// gets there without ever violating it).
//
// Skipped unless TEST_DATABASE_URL is set, so it does not gate CI (which has no
// database). Run locally with, e.g.:
//
//	TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./internal/service/ -run TestUpsertActiveGoalOneActiveInvariant -v
func TestUpsertActiveGoalOneActiveInvariant(t *testing.T) {
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

	email := fmt.Sprintf("plan-test-%d@example.com", time.Now().UnixNano())
	var userID int
	if err := pool.QueryRow(ctx,
		"INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id", email,
	).Scan(&userID); err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}
	defer pool.Exec(ctx, "DELETE FROM users WHERE id = $1", userID)

	if got, err := GetActiveGoal(ctx, pool, userID); err != nil {
		t.Fatalf("GetActiveGoal (no goal yet) failed: %v", err)
	} else if got != nil {
		t.Fatalf("expected no active goal yet, got %+v", got)
	}

	rate1 := 0.5
	goal1, err := UpsertActiveGoal(ctx, pool, &model.WeightGoal{
		UserID: userID, StartWeight: 90, StartDate: "2026-07-01",
		TargetWeight: 80, PaceMode: "rate", RateKgPerWeek: &rate1,
	})
	if err != nil {
		t.Fatalf("UpsertActiveGoal (first) failed: %v", err)
	}
	if goal1.Status != "active" {
		t.Errorf("goal1.Status = %q, want active", goal1.Status)
	}

	rate2 := 0.3
	goal2, err := UpsertActiveGoal(ctx, pool, &model.WeightGoal{
		UserID: userID, StartWeight: 88, StartDate: "2026-07-10",
		TargetWeight: 75, PaceMode: "rate", RateKgPerWeek: &rate2,
	})
	if err != nil {
		t.Fatalf("UpsertActiveGoal (second) failed: %v", err)
	}
	if goal2.Status != "active" {
		t.Errorf("goal2.Status = %q, want active", goal2.Status)
	}
	if goal2.ID == goal1.ID {
		t.Fatal("expected the second upsert to insert a new row, not reuse the first")
	}

	active, err := GetActiveGoal(ctx, pool, userID)
	if err != nil {
		t.Fatalf("GetActiveGoal failed: %v", err)
	}
	if active == nil || active.ID != goal2.ID {
		t.Fatalf("GetActiveGoal = %+v, want goal2 (id %d)", active, goal2.ID)
	}

	var goal1Status string
	if err := pool.QueryRow(ctx, "SELECT status FROM weight_goals WHERE id = $1", goal1.ID).Scan(&goal1Status); err != nil {
		t.Fatalf("failed to read goal1 status: %v", err)
	}
	if goal1Status != "abandoned" {
		t.Errorf("goal1 status = %q, want abandoned", goal1Status)
	}

	if err := AbandonActiveGoal(ctx, pool, userID); err != nil {
		t.Fatalf("AbandonActiveGoal failed: %v", err)
	}
	if got, err := GetActiveGoal(ctx, pool, userID); err != nil {
		t.Fatalf("GetActiveGoal (after abandon) failed: %v", err)
	} else if got != nil {
		t.Fatalf("expected no active goal after AbandonActiveGoal, got %+v", got)
	}
}
