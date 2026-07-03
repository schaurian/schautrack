package database

import (
	"errors"
	"testing"
)

// TestRetrySchemaInitReturnsLastError is a regression guard for the fail-fast
// fix: once all retries are exhausted, retrySchemaInit must RETURN the last
// error (not nil). Returning nil made the caller's error check dead code, so
// the app booted against a partial/missing schema.
func TestRetrySchemaInitReturnsLastError(t *testing.T) {
	boom := errors.New("boom")
	calls := 0

	err := retrySchemaInit(3, 0, func() error {
		calls++
		return boom
	})

	if !errors.Is(err, boom) {
		t.Fatalf("expected the last error to propagate, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
}

// TestRetrySchemaInitSucceedsAfterTransientFailures verifies the loop stops and
// returns nil on the first success, without exhausting the remaining retries.
func TestRetrySchemaInitSucceedsAfterTransientFailures(t *testing.T) {
	calls := 0

	err := retrySchemaInit(5, 0, func() error {
		calls++
		if calls < 3 {
			return errors.New("transient")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected nil after eventual success, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected to stop at the 3rd (successful) attempt, got %d calls", calls)
	}
}
