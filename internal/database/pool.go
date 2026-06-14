package database

import (
	"context"
	"database/sql/driver"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	cfg, err := buildPoolConfig(databaseURL)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return pool, nil
}

// buildPoolConfig parses databaseURL and applies Schautrack's pool tuning.
func buildPoolConfig(databaseURL string) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}

	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnIdleTime = 30 * time.Second
	// Must be > 0. As of pgx v5.10.0, pgxpool enforces MaxConnLifetime at
	// acquire time: a connection's expiry is computed at birth as
	// now + MaxConnLifetime, so MaxConnLifetime == 0 makes every connection
	// "expired" the instant it is acquired. Acquire then destroys and retries
	// maxConns+1 times before failing Ping with "too many failed attempts
	// acquiring connection", crashlooping the app on startup. (Older pgx
	// treated 0 as "no maximum lifetime".)
	cfg.MaxConnLifetime = time.Hour

	// Register custom type: return DATE columns as "YYYY-MM-DD" strings
	// instead of time.Time, to avoid timezone shifting.
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		conn.TypeMap().RegisterType(&pgtype.Type{
			Name:  "date",
			OID:   1082,
			Codec: &dateStringCodec{},
		})
		return nil
	}

	return cfg, nil
}

// dateStringCodec makes pgx scan DATE columns directly into string as "YYYY-MM-DD".
type dateStringCodec struct{}

func (c *dateStringCodec) FormatSupported(format int16) bool {
	return format == pgtype.TextFormatCode
}

func (c *dateStringCodec) PreferredFormat() int16 {
	return pgtype.TextFormatCode
}

func (c *dateStringCodec) PlanEncode(m *pgtype.Map, oid uint32, format int16, value any) pgtype.EncodePlan {
	// Delegate encoding to the default date codec (for parameterized queries)
	return &dateStringEncodePlan{}
}

func (c *dateStringCodec) PlanScan(m *pgtype.Map, oid uint32, format int16, target any) pgtype.ScanPlan {
	return &dateStringScanPlan{}
}

func (c *dateStringCodec) DecodeDatabaseSQLValue(m *pgtype.Map, oid uint32, format int16, src []byte) (driver.Value, error) {
	if src == nil {
		return nil, nil
	}
	return string(src), nil
}

func (c *dateStringCodec) DecodeValue(m *pgtype.Map, oid uint32, format int16, src []byte) (any, error) {
	if src == nil {
		return nil, nil
	}
	return string(src), nil
}

type dateStringScanPlan struct{}

func (p *dateStringScanPlan) Scan(src []byte, target any) error {
	if src == nil {
		switch t := target.(type) {
		case *string:
			*t = ""
		case **string:
			*t = nil
		}
		return nil
	}
	switch t := target.(type) {
	case *string:
		*t = string(src)
	case **string:
		s := string(src)
		*t = &s
	case *any:
		*t = string(src)
	default:
		return fmt.Errorf("dateStringCodec: cannot scan into %T", target)
	}
	return nil
}

type dateStringEncodePlan struct{}

func (p *dateStringEncodePlan) Encode(value any, buf []byte) ([]byte, error) {
	switch v := value.(type) {
	case string:
		return append(buf, []byte(v)...), nil
	case time.Time:
		return append(buf, []byte(v.Format("2006-01-02"))...), nil
	default:
		return nil, fmt.Errorf("dateStringCodec: cannot encode %T", value)
	}
}
