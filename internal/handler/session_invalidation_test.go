package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// fakeExecutor captures Exec calls so we can verify the SQL that
// invalidateUserSessions issues without a live database.
type fakeExecutor struct {
	sqls []string
	args [][]any
}

func (f *fakeExecutor) Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error) {
	f.sqls = append(f.sqls, sql)
	f.args = append(f.args, arguments)
	return pgconn.CommandTag{}, nil
}

func TestInvalidateUserSessions_AllSessions(t *testing.T) {
	f := &fakeExecutor{}
	if err := invalidateUserSessions(context.Background(), f, 42, ""); err != nil {
		t.Fatalf("invalidateUserSessions: %v", err)
	}
	if len(f.sqls) != 1 {
		t.Fatalf("Exec calls = %d, want 1", len(f.sqls))
	}
	sql := f.sqls[0]
	if !strings.Contains(sql, `DELETE FROM "session"`) || !strings.Contains(sql, "userId") {
		t.Errorf("unexpected SQL: %s", sql)
	}
	if strings.Contains(sql, "sid <>") {
		t.Errorf("empty keepSID must delete ALL sessions, got SQL: %s", sql)
	}
	if len(f.args[0]) != 1 || f.args[0][0] != 42 {
		t.Errorf("args = %v, want [42]", f.args[0])
	}
}

func TestInvalidateUserSessions_KeepsCurrentSession(t *testing.T) {
	f := &fakeExecutor{}
	if err := invalidateUserSessions(context.Background(), f, 7, "current-sid"); err != nil {
		t.Fatalf("invalidateUserSessions: %v", err)
	}
	if len(f.sqls) != 1 {
		t.Fatalf("Exec calls = %d, want 1", len(f.sqls))
	}
	sql := f.sqls[0]
	if !strings.Contains(sql, `DELETE FROM "session"`) || !strings.Contains(sql, "sid <>") {
		t.Errorf("expected DELETE excluding current sid, got SQL: %s", sql)
	}
	if len(f.args[0]) != 2 || f.args[0][0] != 7 || f.args[0][1] != "current-sid" {
		t.Errorf("args = %v, want [7 current-sid]", f.args[0])
	}
}
