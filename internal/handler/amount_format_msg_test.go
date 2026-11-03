package handler

import (
	"fmt"
	"testing"
)

// A malformed number and an out-of-range one used to get the same 400,
// "Calories must be between -9999 and 9999". For "12,5" (a comma is only a
// thousands separator) that named a bound the caller had not exceeded.
// Every session-surface path that parses a raw amount must tell them apart.
func TestAmountRejectionsDistinguishFormatFromRange(t *testing.T) {
	rangeMsg := fmt.Sprintf("Calories must be between -%d and %d", MaxEntryCalories, MaxEntryCalories)
	cases := []struct {
		raw  string
		want string
	}{
		{"12,5", InvalidNumberFormatMsg},
		{"abc", InvalidNumberFormatMsg},
		{"10000", rangeMsg},
		{"5000*3", rangeMsg},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			// POST /entries
			if got := classifyAmount(tc.raw, MaxEntryCalories).RejectMsg; got != tc.want {
				t.Errorf("create: RejectMsg = %q, want %q", got, tc.want)
			}
			// POST /entries/{id}/update
			if _, _, msg := buildEntryUpdates(map[string]any{"amount": tc.raw}, false); msg != tc.want {
				t.Errorf("update: msg = %q, want %q", msg, tc.want)
			}
			// POST /api/saved-foods and /api/saved-foods/{id}/update
			if _, _, msg := parseSavedFoodPayload(map[string]any{"name": "x", "amount": tc.raw}, true); msg != tc.want {
				t.Errorf("saved food: msg = %q, want %q", msg, tc.want)
			}
		})
	}
}
