package database

import (
	"os"
	"testing"

	"schautrack/internal/dbtest"
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
// GitHub Actions always sets CI=true, so this fails there and nowhere else.
//
// It asks dbtest.Resolved() rather than reading TEST_DATABASE_URL directly,
// because there are now two ways the integration tests can get a database: the
// `services: postgres` block, or the container internal/dbtest starts when the
// variable is unset. The property worth guarding was never "this specific
// environment variable is set" — it was "the integration tests are actually
// running", and that is what Resolved reports. Checking the variable would now
// fail CI in the one case where everything is in fact working.
func TestIntegrationTestsRunInCI(t *testing.T) {
	if os.Getenv("CI") != "" && !dbtest.Resolved() {
		t.Fatal("no database available in CI (neither TEST_DATABASE_URL nor a dbtest container); " +
			"integration tests are silently skipping")
	}
}
