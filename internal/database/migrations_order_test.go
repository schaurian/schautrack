package database

import (
	"testing"
)

// TestMigrationStepsOrdered guards the sequential-migrations fix: migrations
// used to run in parallel goroutines, which deadlocked (five ALTER TABLE users
// in separate transactions, plus ensureOIDCAccountsSchema upgrading a SHARE
// ROW EXCLUSIVE lock on users to ACCESS EXCLUSIVE against queued siblings).
// They now run as one flat, ordered list. This test pins the ordering
// invariants that matter:
//   - "base" runs first — every other migration REFERENCES or ALTERs the
//     tables it creates (users, calorie_entries, "session")
//   - the data migrations run after "macros", which creates the macro_goals /
//     macros_enabled columns they read
//   - names are unique and functions non-nil, so a failure log like
//     "migration ai_keys: ..." identifies exactly one step
func TestMigrationStepsOrdered(t *testing.T) {
	steps := migrationSteps()
	if len(steps) == 0 {
		t.Fatal("migrationSteps() returned no migrations")
	}

	if steps[0].name != "base" {
		t.Errorf("first migration = %q, want %q (all other migrations depend on its tables)", steps[0].name, "base")
	}

	idx := make(map[string]int, len(steps))
	for i, s := range steps {
		if s.fn == nil {
			t.Errorf("migration %q (index %d) has a nil function", s.name, i)
		}
		if s.name == "" {
			t.Errorf("migration at index %d has an empty name", i)
		}
		if prev, dup := idx[s.name]; dup {
			t.Errorf("duplicate migration name %q at indexes %d and %d", s.name, prev, i)
		}
		idx[s.name] = i
	}

	mustRunBefore := [][2]string{
		// Data migrations read columns created by the macros migration.
		{"macros", "calorie_goal_to_macro_goals"},
		{"macros", "auto_calc_calories"},
		// todos/todo_completions reference users(id) from base.
		{"base", "todos"},
	}
	for _, pair := range mustRunBefore {
		before, after := pair[0], pair[1]
		bi, ok := idx[before]
		if !ok {
			t.Errorf("expected migration %q to exist", before)
			continue
		}
		ai, ok := idx[after]
		if !ok {
			t.Errorf("expected migration %q to exist", after)
			continue
		}
		if bi >= ai {
			t.Errorf("migration %q (index %d) must run before %q (index %d)", before, bi, after, ai)
		}
	}
}

// TestMigrationLockKeyStable pins the pg_advisory_lock key that serializes
// migrations across replicas. The value is arbitrary but must NEVER change:
// during a rolling deploy old and new pods run side by side, and if they
// disagree on the key they can migrate concurrently again — exactly the race
// the lock exists to prevent. 0x7363686175747261 is ASCII "schautra".
func TestMigrationLockKeyStable(t *testing.T) {
	const want int64 = 0x7363686175747261
	if migrationLockKey != want {
		t.Fatalf("migrationLockKey = %#x, want %#x — changing it breaks cross-replica serialization during rolling deploys", migrationLockKey, want)
	}
}
