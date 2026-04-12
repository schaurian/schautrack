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
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Querier abstracts both pool and tx for weight operations.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func UpsertWeightEntry(ctx context.Context, q Querier, userID int, dateStr string, weight float64) (*WeightResult, error) {
	row := q.QueryRow(ctx, `
		INSERT INTO weight_entries (user_id, entry_date, weight)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, entry_date)
			DO UPDATE SET weight = EXCLUDED.weight, updated_at = NOW()
		RETURNING id, entry_date, weight, created_at, updated_at`,
		userID, dateStr, weight)

	var w WeightResult
	err := row.Scan(&w.ID, &w.Date, &w.Weight, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &w, nil
}

func GetWeightEntry(ctx context.Context, pool *pgxpool.Pool, userID int, dateStr string) (*WeightResult, error) {
	var w WeightResult
	err := pool.QueryRow(ctx,
		"SELECT id, entry_date, weight, created_at, updated_at FROM weight_entries WHERE user_id = $1 AND entry_date = $2 LIMIT 1",
		userID, dateStr).Scan(&w.ID, &w.Date, &w.Weight, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &w, nil
}

func GetLastWeightEntry(ctx context.Context, pool *pgxpool.Pool, userID int, beforeOrOnDate string) (*WeightResult, error) {
	query := "SELECT id, entry_date, weight, created_at, updated_at FROM weight_entries WHERE user_id = $1"
	args := []any{userID}
	if beforeOrOnDate != "" {
		query += " AND entry_date <= $2"
		args = append(args, beforeOrOnDate)
	}
	query += " ORDER BY entry_date DESC LIMIT 1"

	var w WeightResult
	err := pool.QueryRow(ctx, query, args...).Scan(&w.ID, &w.Date, &w.Weight, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &w, nil
}
