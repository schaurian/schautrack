package database

import (
	"os"
	"testing"
)

// TestIntegrationTestsRunInCI is the tripwire for the `services: postgres`
// block in the `test` job of .github/workflows/build.yml.
//
// Every DB-backed test in this repo is guarded by
//
//	if os.Getenv("TEST_DATABASE_URL") == "" { t.Skip(...) }
//
// and `go test` reports a skip as a pass. So if the Postgres service is ever
// removed — or its credentials/port drift out of sync with the env var on the
// "Run Go tests" step — CI stays green while quietly testing nothing. That
// includes TestRunAllMigrationsIdempotentBodyProfileAndWeightGoals, the only
// automated proof that migrations survive the re-run they get on every
// container start.
//
// GitHub Actions always sets CI=true, so this fails there and nowhere else:
// a plain local `go test ./...` (CI unset) is unaffected and the integration
// tests keep skipping as before.
func TestIntegrationTestsRunInCI(t *testing.T) {
	if os.Getenv("CI") != "" && os.Getenv("TEST_DATABASE_URL") == "" {
		t.Fatal("TEST_DATABASE_URL must be set in CI; integration tests are silently skipping")
	}
}
