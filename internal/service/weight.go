package service

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type WeightResult struct {
	ID        int       `json:"id"`
	Date      string    `json:"entry_date"`
	Weight    float64   `json:"weight"`
	BodyFat   *float64  `json:"body_fat"` // percent, nil when not measured
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// weightColumns is the shared SELECT list, so a column added to WeightResult
// cannot be forgotten in one of the three readers below.
const weightColumns = "id, entry_date, weight, body_fat, created_at, updated_at"

// Querier abstracts both pool and tx for weight operations.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// BodyFatUpdate is the three-state intent a weight upsert carries for the
// optional body-fat reading. Weight is always written; body fat must be able to
// stay untouched, because a weight-only save (the dashboard's weight input, the
// generic POST /entries, an import) must never silently wipe a reading taken
// from the same day's scale.
//
//	BodyFatUpdate{}                      // leave whatever is stored alone
//	BodyFatUpdate{Set: true}             // clear it
//	BodyFatUpdate{Set: true, Value: &v}  // set it to v
type BodyFatUpdate struct {
	Set   bool
	Value *float64
}

// KeepBodyFat is the zero-value BodyFatUpdate, named for call sites that only
// deal in weight.
var KeepBodyFat = BodyFatUpdate{}

func UpsertWeightEntry(ctx context.Context, q Querier, userID int, dateStr string, weight float64, bodyFat BodyFatUpdate) (*WeightResult, error) {
	// The CASE resolves the three states inside the single statement rather
	// than reading the row first, so two concurrent saves for the same day
	// cannot interleave into a lost update.
	row := q.QueryRow(ctx, `
		INSERT INTO weight_entries (user_id, entry_date, weight, body_fat)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, entry_date)
			DO UPDATE SET
				weight = EXCLUDED.weight,
				body_fat = CASE WHEN $5 THEN EXCLUDED.body_fat ELSE weight_entries.body_fat END,
				updated_at = NOW()
		RETURNING `+weightColumns,
		userID, dateStr, weight, bodyFat.Value, bodyFat.Set)

	var w WeightResult
	err := row.Scan(&w.ID, &w.Date, &w.Weight, &w.BodyFat, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

func GetWeightEntry(ctx context.Context, pool *pgxpool.Pool, userID int, dateStr string) (*WeightResult, error) {
	var w WeightResult
	err := pool.QueryRow(ctx,
		"SELECT "+weightColumns+" FROM weight_entries WHERE user_id = $1 AND entry_date = $2 LIMIT 1",
		userID, dateStr).Scan(&w.ID, &w.Date, &w.Weight, &w.BodyFat, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &w, nil
}

func GetLastWeightEntry(ctx context.Context, pool *pgxpool.Pool, userID int, beforeOrOnDate string) (*WeightResult, error) {
	query := "SELECT " + weightColumns + " FROM weight_entries WHERE user_id = $1"
	args := []any{userID}
	if beforeOrOnDate != "" {
		query += " AND entry_date <= $2"
		args = append(args, beforeOrOnDate)
	}
	query += " ORDER BY entry_date DESC LIMIT 1"

	var w WeightResult
	err := pool.QueryRow(ctx, query, args...).Scan(&w.ID, &w.Date, &w.Weight, &w.BodyFat, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &w, nil
}

// GetLastBodyFatEntry returns the most recent entry that actually carries a
// body-fat reading on or before a date. Body fat is measured less often than
// weight (many users only step on the composition scale weekly), so the plan
// falls back to the last reading that exists rather than showing nothing the
// moment a weight-only day is logged.
func GetLastBodyFatEntry(ctx context.Context, pool *pgxpool.Pool, userID int, beforeOrOnDate string) (*WeightResult, error) {
	query := "SELECT " + weightColumns + " FROM weight_entries WHERE user_id = $1 AND body_fat IS NOT NULL"
	args := []any{userID}
	if beforeOrOnDate != "" {
		query += " AND entry_date <= $2"
		args = append(args, beforeOrOnDate)
	}
	query += " ORDER BY entry_date DESC LIMIT 1"

	var w WeightResult
	err := pool.QueryRow(ctx, query, args...).Scan(&w.ID, &w.Date, &w.Weight, &w.BodyFat, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &w, nil
}
