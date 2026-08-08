package database

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoTestBuildsABarePool is the tripwire for #355 and #412.
//
// database.NewPool is not pgxpool.New plus tuning: its AfterConnect registers
// dateStringCodec for OID 1082, so a DATE column scans straight into a string
// as YYYY-MM-DD instead of a time.Time (see pool.go — it exists to avoid
// timezone shifting). A test that opens its own pool with a bare
// pgxpool.New does not get that codec, so any handler scanning a date into a
// string field fails with
//
//	cannot scan date (OID 1082) in binary format into *string
//
// which is a 500 the running app cannot produce. The test then either fails for
// a reason that does not exist in production, or — worse — passes while
// exercising a pool that behaves differently from the one it claims to model.
//
// Cheaper to forbid than to rediscover: both issues above were found by someone
// hitting the error while writing an unrelated test.
func TestNoTestBuildsABarePool(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolving the repo root: %v", err)
	}
	self := "test_pool_guard_test.go"

	var offenders []string
	err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// node_modules is enormous and contains no Go.
			if info.Name() == "node_modules" || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(info.Name(), "_test.go") || info.Name() == self {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "pgxpool.New(") {
			rel, _ := filepath.Rel(root, path)
			offenders = append(offenders, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repo: %v", err)
	}
	for _, f := range offenders {
		t.Errorf("%s builds a pool with pgxpool.New; use database.NewPool so the test gets "+
			"the DATE codec production installs", f)
	}
}

// TestNewPoolRegistersTheDateCodec proves the thing the guard above protects.
// Without it the guard is a style rule; with it, a change to NewPool that drops
// AfterConnect fails here rather than in whichever handler test next scans a
// date.
func TestNewPoolRegistersTheDateCodec(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := NewPool(ctx, url)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	// The whole point: a DATE comes back as a string, not a time.Time.
	var got string
	if err := pool.QueryRow(ctx, "SELECT DATE '2026-08-05'").Scan(&got); err != nil {
		t.Fatalf("scanning a DATE into a string: %v — the dateStringCodec is not registered", err)
	}
	if got != "2026-08-05" {
		t.Errorf("DATE scanned as %q, want \"2026-08-05\"", got)
	}
}
