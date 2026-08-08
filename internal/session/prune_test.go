package session

import (
	"context"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// The prune loop had no tests at all before these, and the reason was purely
// mechanical: PruneInterval is five minutes, so asserting that a second tick
// happens meant a ten-minute test. Under synctest the clock is fake and only
// advances once every goroutine in the bubble is durably blocked, so the same
// assertions run instantly and — more importantly — deterministically. There
// is no sleep-and-hope margin to tune, and nothing to go flaky on a loaded CI
// runner.
//
// What is being protected: expired rows are what stop the "session" table
// growing without bound. Every cookie-less request that does write session
// data leaves a row behind, and only this loop removes them. If it silently
// stopped ticking, nothing would fail — the table would just grow until
// queries against it slowed down in production.

func TestPruneLoopDeletesExpiredSessionsOnEveryTick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := &fakeDB{}
		s := &Store{pool: db}

		go s.pruneLoop(t.Context())

		// Nothing may be deleted before the first interval elapses. Wait for
		// the loop to reach its blocking select first, otherwise this asserts
		// against a goroutine that has not started yet and would pass even if
		// the loop pruned immediately.
		synctest.Wait()
		if got := len(db.recorded()); got != 0 {
			t.Fatalf("prune ran %d times before the first interval elapsed, want 0", got)
		}

		// Advancing to exactly the interval is enough: the fake clock fires
		// the ticker at PruneInterval, not at PruneInterval+ε.
		time.Sleep(PruneInterval)
		synctest.Wait()

		execs := db.recorded()
		if len(execs) != 1 {
			t.Fatalf("after one interval the loop ran %d times, want exactly 1: %v", len(execs), execs)
		}
		if !strings.Contains(execs[0], `DELETE FROM "session"`) {
			t.Errorf("statement = %q, want a DELETE against the session table", execs[0])
		}
		if !strings.Contains(execs[0], "expire < NOW()") {
			t.Errorf("statement = %q, want it bounded by expire < NOW() — an unbounded DELETE "+
				"would sign out every logged-in user", execs[0])
		}

		// A ticker that fires once and stops looks identical to a working one
		// in any single-tick test, so assert the loop keeps going.
		time.Sleep(3 * PruneInterval)
		synctest.Wait()
		if got := len(db.recorded()); got != 4 {
			t.Fatalf("after four intervals the loop ran %d times, want 4 — the ticker stopped firing", got)
		}
	})
}

// A cancelled context must stop the loop. This is what lets the bubble above
// finish (synctest.Test waits for every goroutine to exit, and a loop that
// ignored cancellation would deadlock the test rather than leak silently), and
// in production it is the shutdown path the loop previously did not have.
func TestPruneLoopStopsOnContextCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		db := &fakeDB{}
		s := &Store{pool: db}

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.pruneLoop(ctx)
		}()

		time.Sleep(PruneInterval)
		synctest.Wait()
		if got := len(db.recorded()); got != 1 {
			t.Fatalf("prune ran %d times before cancellation, want 1", got)
		}

		cancel()
		synctest.Wait()

		select {
		case <-done:
		default:
			t.Fatal("pruneLoop is still running after its context was cancelled")
		}

		// No further pruning after cancellation, however much time passes.
		time.Sleep(10 * PruneInterval)
		synctest.Wait()
		if got := len(db.recorded()); got != 1 {
			t.Fatalf("prune ran %d times after cancellation, want it to stay at 1", got)
		}
	})
}
