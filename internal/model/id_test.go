package model

import (
	"strconv"
	"testing"
)

// TestParseIDRejectsValuesTooLargeForInt4 is the regression test for the bug
// the OpenAPI contract fuzzer found: an id above int4's range parsed cleanly,
// passed a `> 0` check, and only failed at the driver, producing a 500 where a
// 404 belongs.
func TestParseIDRejectsValuesTooLargeForInt4(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int
		ok   bool
	}{
		{"a normal id", "42", 42, true},
		{"the smallest valid id", "1", 1, true},
		{"the largest value int4 holds", strconv.Itoa(MaxID), MaxID, true},

		// The regression. Each of these previously reached Postgres and came
		// back as "unable to encode N into binary format for int4 (OID 23)".
		{"one past int4", strconv.Itoa(MaxID + 1), 0, false},
		{"the id from DELETE /entries/{id}", "34359738367", 0, false},
		{"the user param from GET /todos", "1248349573196321792", 0, false},
		{"the id from POST /saved-foods/{id}/track", "2403310975", 0, false},

		{"zero", "0", 0, false},
		{"negative", "-1", 0, false},
		{"empty", "", 0, false},
		{"not a number", "abc", 0, false},
		{"float", "1.5", 0, false},
		{"leading plus is not an id", "+1", 1, true}, // strconv.Atoi accepts it; harmless
		{"beyond int64 entirely", "99999999999999999999999", 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseID(tc.in)
			if ok != tc.ok {
				t.Fatalf("ParseID(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			}
			if got != tc.want {
				t.Errorf("ParseID(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
