// Package dbtest resolves the Postgres instance that integration tests run
// against, starting a throwaway container when nothing else is available.
//
// # Why this exists
//
// Every DB-backed test in this repo is guarded by
//
//	if os.Getenv("TEST_DATABASE_URL") == "" { t.Skip(...) }
//
// and `go test` reports a skip as a pass. That is a bad default in two
// directions. In CI it needed a tripwire (TestIntegrationTestsRunInCI) to stop
// the whole integration suite silently disappearing behind a green check. And
// locally it means `go test ./...` quietly exercises none of the migrations,
// none of the /api/v1 handlers against a real schema, and none of the
// constraint behaviour — unless the developer happens to know the incantation
// and has a Postgres 18 running on the right port. The usual result is that
// the tests most worth running are the ones that never run before a push.
//
// Run removes the setup step: if TEST_DATABASE_URL is not already set and
// Docker is available, it starts a Postgres container, points the existing
// env-var plumbing at it, and tears it down when the package's tests finish.
// Nothing about the individual tests changes.
//
// # Why not testcontainers-go
//
// It is the obvious library for this and it does the job well. It also brings
// 88 modules and 52 require lines with it, against a module whose entire
// current graph is 44 modules and 26 require lines — and this repo has, very
// deliberately, no test dependencies at all: no testify, no assert helpers,
// nothing. Tripling the dependency graph for `docker run` plus a readiness
// poll is a poor trade here. The subset actually needed is below and is not
// subtle.
//
// If the ecosystem parts (Ryuk-based orphan reaping, module presets, reusable
// containers) ever become worth having, swapping this file for
// testcontainers-go is a contained change: Run and Resolved are the only entry
// points.
package dbtest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// EnvVar is the connection string tests read. Kept as the single source of
// truth so a container started here is indistinguishable, to the tests, from a
// database the developer or CI supplied.
const EnvVar = "TEST_DATABASE_URL"

// image must track the Postgres major the app actually runs against
// (compose.test.yml, the Helm chart, and the `services: postgres` block in
// build.yml). Testing migrations against a different major tests the wrong DDL
// semantics — the same reason that block pins a major rather than using
// `postgres:latest`.
const image = "postgres:18"

// startupTimeout bounds the readiness poll. Generous because the first run on
// a machine includes pulling the image.
const startupTimeout = 3 * time.Minute

// Resolved reports whether integration tests have a database to run against —
// either one supplied via the environment or one Run started.
//
// The CI guard uses this rather than checking the env var directly: what
// matters is "the integration tests are really running", not which of the two
// mechanisms got them a database.
func Resolved() bool { return os.Getenv(EnvVar) != "" }

// URL returns the integration-test connection string, skipping the test when
// there is none. Equivalent to the hand-rolled getenv-and-skip the tests
// already do; provided so new tests have one obvious way to ask.
func URL(t *testing.T) string {
	t.Helper()
	url := os.Getenv(EnvVar)
	if url == "" {
		t.Skipf("%s not set and no container could be started; skipping integration test", EnvVar)
	}
	return url
}

// Run is the TestMain body for packages with DB-backed tests:
//
//	func TestMain(m *testing.M) { os.Exit(dbtest.Run(m)) }
//
// It leaves an externally supplied TEST_DATABASE_URL completely alone, so CI's
// service container and a developer's own database both keep working and cost
// nothing. Only when the variable is empty does it try Docker, and if Docker
// is unavailable it runs the tests anyway — they skip exactly as they did
// before, which keeps this from becoming a hard Docker dependency for people
// running unit tests on a plane.
func Run(m *testing.M) int {
	if os.Getenv(EnvVar) != "" {
		return m.Run()
	}
	if !dockerAvailable() {
		fmt.Fprintf(os.Stderr,
			"dbtest: %s is unset and Docker is unavailable; DB-backed tests will skip\n", EnvVar)
		return m.Run()
	}

	url, stop, err := startPostgres()
	if err != nil {
		// Deliberately not fatal. A broken Docker setup should degrade to the
		// previous behaviour (skipped integration tests), not block someone
		// from running the unit tests in the same package.
		fmt.Fprintf(os.Stderr, "dbtest: could not start %s (%v); DB-backed tests will skip\n", image, err)
		return m.Run()
	}
	defer stop()

	os.Setenv(EnvVar, url)
	defer os.Unsetenv(EnvVar)

	return m.Run()
}

func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// `docker info` rather than `docker version`: the latter succeeds against a
	// client with no reachable daemon.
	return exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").Run() == nil
}

// startPostgres launches a throwaway Postgres and returns its URL plus a
// teardown function.
func startPostgres() (string, func(), error) {
	// --publish-all assigns a free host port instead of a fixed one, so
	// concurrent `go test ./...` packages (which run as separate binaries, each
	// with its own TestMain) cannot collide on 5432 — and neither can a
	// developer's own Postgres already bound to it.
	//
	// fsync=off and full_page_writes=off are safe here and materially faster:
	// the entire database is discarded when the container stops, so there is
	// nothing to survive a crash.
	out, err := run(30*time.Second, "docker", "run", "--detach", "--rm",
		"--publish-all",
		"--env", "POSTGRES_PASSWORD=postgres",
		"--env", "POSTGRES_USER=postgres",
		"--env", "POSTGRES_DB=postgres",
		image,
		"-c", "fsync=off",
		"-c", "full_page_writes=off",
	)
	if err != nil {
		return "", nil, fmt.Errorf("docker run: %w", err)
	}
	id := strings.TrimSpace(out)
	stop := func() {
		_, _ = run(30*time.Second, "docker", "rm", "--force", "--volumes", id)
	}

	port, err := hostPort(id)
	if err != nil {
		stop()
		return "", nil, err
	}

	url := fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%s/postgres?sslmode=disable", port)
	if err := waitReady(id); err != nil {
		stop()
		return "", nil, err
	}
	return url, stop, nil
}

// hostPort resolves the ephemeral host port Docker bound to Postgres's 5432.
func hostPort(id string) (string, error) {
	out, err := run(15*time.Second, "docker", "port", id, "5432/tcp")
	if err != nil {
		return "", fmt.Errorf("docker port: %w", err)
	}
	// Output is one "addr:port" per binding (IPv4 and possibly IPv6). Take the
	// port from the first line; both bindings share it.
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	i := strings.LastIndex(line, ":")
	if i < 0 || i == len(line)-1 {
		return "", fmt.Errorf("docker port returned %q, which has no port", out)
	}
	return line[i+1:], nil
}

// waitReady polls until Postgres accepts queries over TCP.
//
// The -h 127.0.0.1 is the entire point and was the bug. The postgres
// entrypoint runs initdb, starts a temporary server for the init scripts, then
// stops it and starts the real one — and that temporary server listens on the
// unix socket ONLY. `pg_isready` with no host defaults to the socket, so it
// reports ready during the init phase, before anything is listening on TCP.
// Tests connect over the published port, so they got either a refused
// connection or the temporary server's "unexpected EOF" as it shut down. It
// reproduces as an intermittent
//
//	failed to receive message: unexpected EOF
//
// on a loaded machine, where the window between the two phases is widest.
// Measured on an idle laptop the socket reports ready a full poll before TCP
// does, so the race was always there and only load made it visible.
//
// The probe is `psql -c 'SELECT 1'` rather than pg_isready because it has to
// prove more than a listening socket: pg_isready reports "accepting
// connections" while the server is still in recovery, and a query is the thing
// the tests actually need to work.
func waitReady(id string) error {
	deadline := time.Now().Add(startupTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		_, err := run(10*time.Second, "docker", "exec", id,
			"psql", "--host", "127.0.0.1", "--port", "5432",
			"--username", "postgres", "--dbname", "postgres",
			"--quiet", "--no-align", "--tuples-only", "--command", "SELECT 1")
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("%s was not ready within %v: %w", image, startupTimeout, lastErr)
}

func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err,
			strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}
