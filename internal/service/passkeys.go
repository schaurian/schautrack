package service

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const MaxPasskeys = 10

type PasskeyRecord struct {
	ID              int
	UserID          int
	CredentialID    []byte
	PublicKey       []byte
	AttestationType string
	Transports      string
	Name            string
	SignCount       int
	AAGUID          []byte
	CreatedAt       time.Time
	LastUsedAt      *time.Time
}

func CreatePasskey(ctx context.Context, pool *pgxpool.Pool, userID int, credID, pubKey []byte, attestationType, transports, name string, signCount int, aaguid []byte) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO user_passkeys (user_id, credential_id, public_key, attestation_type, transports, name, sign_count, aaguid)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		userID, credID, pubKey, attestationType, transports, name, signCount, aaguid)
	return err
}

func FindPasskeyByCredentialID(ctx context.Context, pool *pgxpool.Pool, credID []byte) (*PasskeyRecord, error) {
	var p PasskeyRecord
	err := pool.QueryRow(ctx,
		`SELECT id, user_id, credential_id, public_key, COALESCE(attestation_type, ''), COALESCE(transports, ''),
		        name, sign_count, aaguid, created_at, last_used_at
		 FROM user_passkeys WHERE credential_id = $1`, credID).
		Scan(&p.ID, &p.UserID, &p.CredentialID, &p.PublicKey, &p.AttestationType, &p.Transports,
			&p.Name, &p.SignCount, &p.AAGUID, &p.CreatedAt, &p.LastUsedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func ListPasskeys(ctx context.Context, pool *pgxpool.Pool, userID int) ([]PasskeyRecord, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, user_id, credential_id, public_key, COALESCE(attestation_type, ''), COALESCE(transports, ''),
		        name, sign_count, aaguid, created_at, last_used_at
		 FROM user_passkeys WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var passkeys []PasskeyRecord
	for rows.Next() {
		var p PasskeyRecord
		if err := rows.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.PublicKey, &p.AttestationType, &p.Transports,
			&p.Name, &p.SignCount, &p.AAGUID, &p.CreatedAt, &p.LastUsedAt); err != nil {
			return nil, err
		}
		passkeys = append(passkeys, p)
	}
	return passkeys, nil
}

func CountPasskeys(ctx context.Context, pool *pgxpool.Pool, userID int) (int, error) {
	var count int
	err := pool.QueryRow(ctx,
		"SELECT count(*) FROM user_passkeys WHERE user_id = $1", userID).Scan(&count)
	return count, err
}

func DeletePasskey(ctx context.Context, pool *pgxpool.Pool, id, userID int) error {
	_, err := pool.Exec(ctx,
		"DELETE FROM user_passkeys WHERE id = $1 AND user_id = $2", id, userID)
	return err
}

func RenamePasskey(ctx context.Context, pool *pgxpool.Pool, id, userID int, name string) error {
	_, err := pool.Exec(ctx,
		"UPDATE user_passkeys SET name = $1 WHERE id = $2 AND user_id = $3", name, id, userID)
	return err
}

func UpdatePasskeyUsage(ctx context.Context, pool *pgxpool.Pool, credID []byte, signCount int) error {
	_, err := pool.Exec(ctx,
		"UPDATE user_passkeys SET sign_count = $1, last_used_at = NOW() WHERE credential_id = $2",
		signCount, credID)
	return err
}

func HasPassword(ctx context.Context, pool *pgxpool.Pool, userID int) (bool, error) {
	var hash *string
	err := pool.QueryRow(ctx,
		"SELECT password_hash FROM users WHERE id = $1", userID).Scan(&hash)
	if err != nil {
		return false, err
	}
	return hash != nil && *hash != "", nil
}
