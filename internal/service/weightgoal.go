package service

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/model"
)

const weightGoalColumns = `id, user_id, start_weight, start_date, target_weight, pace_mode,
	rate_kg_per_week, target_date, activity_level, status, achieved_at, created_at, updated_at`

func scanWeightGoal(row pgx.Row) (*model.WeightGoal, error) {
	var g model.WeightGoal
	err := row.Scan(
		&g.ID, &g.UserID, &g.StartWeight, &g.StartDate, &g.TargetWeight, &g.PaceMode,
		&g.RateKgPerWeek, &g.TargetDate, &g.ActivityLevel, &g.Status, &g.AchievedAt, &g.CreatedAt, &g.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// GetActiveGoal returns the user's active weight goal, or nil if none exists.
func GetActiveGoal(ctx context.Context, pool *pgxpool.Pool, userID int) (*model.WeightGoal, error) {
	row := pool.QueryRow(ctx,
		"SELECT "+weightGoalColumns+" FROM weight_goals WHERE user_id = $1 AND status = 'active' LIMIT 1",
		userID)
	g, err := scanWeightGoal(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return g, nil
}

// UpsertActiveGoal abandons any existing active goal for the user and inserts
// a new one, guaranteeing the one-active-goal-per-user invariant.
func UpsertActiveGoal(ctx context.Context, pool *pgxpool.Pool, g *model.WeightGoal) (*model.WeightGoal, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		"UPDATE weight_goals SET status = 'abandoned', updated_at = NOW() WHERE user_id = $1 AND status = 'active'",
		g.UserID); err != nil {
		return nil, err
	}

	row := tx.QueryRow(ctx, `
		INSERT INTO weight_goals (user_id, start_weight, start_date, target_weight, pace_mode, rate_kg_per_week, target_date, activity_level, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active')
		RETURNING `+weightGoalColumns,
		g.UserID, g.StartWeight, g.StartDate, g.TargetWeight, g.PaceMode, g.RateKgPerWeek, g.TargetDate, g.ActivityLevel)
	saved, err := scanWeightGoal(row)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return saved, nil
}

// AbandonActiveGoal marks the user's active goal (if any) as abandoned.
func AbandonActiveGoal(ctx context.Context, pool *pgxpool.Pool, userID int) error {
	_, err := pool.Exec(ctx,
		"UPDATE weight_goals SET status = 'abandoned', updated_at = NOW() WHERE user_id = $1 AND status = 'active'",
		userID)
	return err
}

// MarkGoalAchieved marks a goal as achieved.
func MarkGoalAchieved(ctx context.Context, pool *pgxpool.Pool, goalID int) error {
	_, err := pool.Exec(ctx,
		"UPDATE weight_goals SET status = 'achieved', achieved_at = NOW() WHERE id = $1",
		goalID)
	return err
}

// UpdateBodyMetrics writes the user's body-profile fields used by the planner.
func UpdateBodyMetrics(ctx context.Context, pool *pgxpool.Pool, userID int, heightCm *float64, birthYear *int, sex, activity *string) error {
	_, err := pool.Exec(ctx,
		"UPDATE users SET height_cm = $2, birth_year = $3, sex = $4, activity_level = $5 WHERE id = $1",
		userID, heightCm, birthYear, sex, activity)
	return err
}

// GetWeightSeries returns the user's logged weight entries on or after sinceDate, ordered ascending.
func GetWeightSeries(ctx context.Context, pool *pgxpool.Pool, userID int, sinceDate string) ([]WeightPoint, error) {
	rows, err := pool.Query(ctx,
		"SELECT entry_date, weight FROM weight_entries WHERE user_id = $1 AND entry_date >= $2 ORDER BY entry_date",
		userID, sinceDate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pts []WeightPoint
	for rows.Next() {
		var dateStr string
		var weight float64
		if err := rows.Scan(&dateStr, &weight); err != nil {
			continue
		}
		d, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			continue
		}
		pts = append(pts, WeightPoint{Date: d, Weight: weight})
	}
	return pts, rows.Err()
}
