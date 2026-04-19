package service

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type OIDCAccount struct {
	ID        int
	UserID    int
	Provider  string
	Subject   string
	Email     string
	CreatedAt string
}

func FindOIDCAccount(ctx context.Context, pool *pgxpool.Pool, provider, subject string) (*OIDCAccount, error) {
	var a OIDCAccount
	err := pool.QueryRow(ctx,
		"SELECT id, user_id, provider, subject, email FROM user_oidc_accounts WHERE provider = $1 AND subject = $2",
		provider, subject).Scan(&a.ID, &a.UserID, &a.Provider, &a.Subject, &a.Email)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func CreateOIDCAccount(ctx context.Context, pool *pgxpool.Pool, userID int, provider, subject, email string) error {
	_, err := pool.Exec(ctx,
		"INSERT INTO user_oidc_accounts (user_id, provider, subject, email) VALUES ($1, $2, $3, $4) ON CONFLICT (provider, subject) DO NOTHING",
		userID, provider, subject, email)
	return err
}

func ListOIDCAccounts(ctx context.Context, pool *pgxpool.Pool, userID int) ([]OIDCAccount, error) {
	rows, err := pool.Query(ctx,
		"SELECT id, user_id, provider, subject, COALESCE(email, '') FROM user_oidc_accounts WHERE user_id = $1 ORDER BY created_at", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var accounts []OIDCAccount
	for rows.Next() {
		var a OIDCAccount
		if err := rows.Scan(&a.ID, &a.UserID, &a.Provider, &a.Subject, &a.Email); err != nil {
			return nil, err
		}
		accounts = append(accounts, a)
	}
	return accounts, nil
}

func DeleteOIDCAccount(ctx context.Context, pool *pgxpool.Pool, id, userID int) error {
	_, err := pool.Exec(ctx,
		"DELETE FROM user_oidc_accounts WHERE id = $1 AND user_id = $2", id, userID)
	return err
}

func CountOIDCAccounts(ctx context.Context, pool *pgxpool.Pool, userID int) (int, error) {
	var count int
	err := pool.QueryRow(ctx,
		"SELECT count(*) FROM user_oidc_accounts WHERE user_id = $1", userID).Scan(&count)
	return count, err
}
