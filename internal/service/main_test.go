package service

import (
	"os"
	"testing"

	"schautrack/internal/dbtest"
)

// TestMain gives this package's DB-backed tests a database to run against.
// When TEST_DATABASE_URL is already set (CI, or a developer's own Postgres) it
// changes nothing; otherwise it starts a throwaway Postgres container for the
// lifetime of this test binary. See internal/dbtest.
func TestMain(m *testing.M) {
	os.Exit(dbtest.Run(m))
}
