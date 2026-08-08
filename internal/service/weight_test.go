package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestParseWeightValid(t *testing.T) {
	tests := []struct {
		input string
		value float64
	}{
		{"75.5", 75.5},
		{"100", 100.0},
		{"0.1", 0.1},
		{"1", 1.0},
		{"999.99", 999.99},
		{"1500", 1500.0},
		{"  42.5  ", 42.5},
	}
	for _, tt := range tests {
		r := ParseWeight(tt.input)
		if !r.Ok {
			t.Errorf("ParseWeight(%q) = not ok, want ok with value %v", tt.input, tt.value)
			continue
		}
		if r.Value != tt.value {
			t.Errorf("ParseWeight(%q).Value = %v, want %v", tt.input, r.Value, tt.value)
		}
	}
}

func TestParseWeightInvalid(t *testing.T) {
	tests := []struct {
		input string
		desc  string
	}{
		{"", "empty string"},
		{"abc", "non-numeric"},
		{"-1", "negative"},
		{"0", "zero"},
		{"1501", "exceeds max (1500)"},
		{"   ", "whitespace only"},
		{"12.34.56", "multiple dots"},
		{"NaN", "NaN string"},
		{"Inf", "infinity string"},
	}
	for _, tt := range tests {
		r := ParseWeight(tt.input)
		if r.Ok {
			t.Errorf("ParseWeight(%q) [%s] = ok with value %v, want not ok", tt.input, tt.desc, r.Value)
		}
	}
}

func TestParseWeightCommaDecimal(t *testing.T) {
	// European-style comma decimal separator
	r := ParseWeight("75,5")
	if !r.Ok || r.Value != 75.5 {
		t.Errorf("ParseWeight(\"75,5\") = {ok: %v, value: %v}, want {ok: true, value: 75.5}", r.Ok, r.Value)
	}
}

func TestParseWeightRounding(t *testing.T) {
	// ParseWeight rounds to 2 decimal places
	tests := []struct {
		input string
		value float64
	}{
		{"75.555", 75.56},
		{"75.554", 75.55},
		{"75.5", 75.5},
	}
	for _, tt := range tests {
		r := ParseWeight(tt.input)
		if !r.Ok || r.Value != tt.value {
			t.Errorf("ParseWeight(%q) = {ok: %v, value: %v}, want {ok: true, value: %v}", tt.input, r.Ok, r.Value, tt.value)
		}
	}
}

func TestParseWeightTooLong(t *testing.T) {
	// Input longer than 12 chars after comma normalization
	r := ParseWeight("1234567890123")
	if r.Ok {
		t.Errorf("ParseWeight with >12 char input should be rejected")
	}
}

func TestParseBodyFat(t *testing.T) {
	valid := []struct {
		input string
		value float64
	}{
		{"24.3", 24.3},
		{"18", 18},
		{"  31.5  ", 31.5},
		{"22,7", 22.7},  // European comma decimal, like ParseWeight
		{"24.36", 24.4}, // rounded to the NUMERIC(4,1) column
		{"24.34", 24.3},
		{"75", 75}, // exactly at MaxBodyFatPct
		{"0.1", 0.1},
		{"0.05", 0.1}, // first value that rounds up to 0.1
	}
	for _, tt := range valid {
		got, ok := ParseBodyFat(tt.input)
		assertOkImpliesPositive(t, "ParseBodyFat", tt.input, ok, got)
		if !ok {
			t.Errorf("ParseBodyFat(%q) = not ok, want %v", tt.input, tt.value)
			continue
		}
		if got != tt.value {
			t.Errorf("ParseBodyFat(%q) = %v, want %v", tt.input, got, tt.value)
		}
	}

	invalid := []struct{ input, desc string }{
		{"", "empty"},
		{"   ", "whitespace only"},
		{"abc", "non-numeric"},
		{"0", "zero"},
		{"-5", "negative"},
		{"75.1", "just above the 75% ceiling"},
		// The ceiling is checked before rounding, so a value that would round
		// back down to 75.0 is still out of range as typed. Pinned deliberately:
		// the parser is strict at both ends rather than silently accepting an
		// input the user can see is above the limit.
		{"75.04", "above the ceiling even though it rounds to 75.0"},
		{"100", "a percentage no body can reach"},
		{"NaN", "NaN string"},
		{"Inf", "infinity string"},
		{"1234567890123", "longer than 12 chars"},
		// Rounding boundary: ParseBodyFat rounds to one decimal, so anything
		// below 0.05 rounds to exactly 0 — which
		// CHECK (body_fat > 0 AND body_fat <= 75) rejects. The parser must
		// refuse these itself so the failure is a 400, not a 500.
		{"0.01", "rounds to 0"},
		{"0.04", "rounds to 0"},
		{"0.0499", "rounds to 0"},
		{"1e-07", "rounds to 0"},
	}
	for _, tt := range invalid {
		got, ok := ParseBodyFat(tt.input)
		assertOkImpliesPositive(t, "ParseBodyFat", tt.input, ok, got)
		if ok {
			t.Errorf("ParseBodyFat(%q) [%s] = %v, want not ok", tt.input, tt.desc, got)
		}
	}
}

// --- three-state weight write path -----------------------------------------

// fakeRow satisfies pgx.Row. A nil err fills the six weightColumns
// destinations with recognizable values so the happy path can Scan.
type fakeRow struct {
	err     error
	bodyFat *float64
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 6 {
		return fmt.Errorf("scan into %d destinations, want the 6 of weightColumns", len(dest))
	}
	*dest[0].(*int) = 7
	*dest[1].(*string) = "2026-08-08"
	*dest[2].(*float64) = 82.0
	*dest[3].(**float64) = r.bodyFat
	*dest[4].(*time.Time) = time.Unix(0, 0).UTC()
	*dest[5].(*time.Time) = time.Unix(0, 0).UTC()
	return nil
}

// fakeQuerier records the single statement the upsert issues, which is what
// these tests are really about: which columns the write touches.
type fakeQuerier struct {
	sql  string
	args []any
	row  pgx.Row
}

func (q *fakeQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	q.sql, q.args = sql, args
	return q.row
}

func TestUpsertWeightEntryWritesWeight(t *testing.T) {
	q := &fakeQuerier{row: fakeRow{}}
	pct := 24.3
	if _, err := UpsertWeightEntry(context.Background(), q, 3, "2026-08-08", 82.0, BodyFatUpdate{Set: true, Value: &pct}); err != nil {
		t.Fatalf("UpsertWeightEntry: %v", err)
	}
	if !strings.Contains(q.sql, "INSERT INTO weight_entries") {
		t.Errorf("a caller that measured a weight must insert-or-update; got:\n%s", q.sql)
	}
	if !strings.Contains(q.sql, "weight = EXCLUDED.weight") {
		t.Errorf("weight must be written unconditionally on this path; got:\n%s", q.sql)
	}
	want := []any{3, "2026-08-08", 82.0, &pct, true}
	if len(q.args) != len(want) {
		t.Fatalf("args = %v, want %v", q.args, want)
	}
	for i := range want {
		if fmt.Sprintf("%v", q.args[i]) != fmt.Sprintf("%v", want[i]) {
			t.Errorf("arg %d = %v, want %v", i, q.args[i], want[i])
		}
	}
}

func TestUpsertWeightEntryPartialKeepWeightLeavesWeightAlone(t *testing.T) {
	// The regression this whole three-state weight exists for: a body-fat-only
	// save must not carry a weight, so it cannot revert one logged elsewhere.
	pct := 24.3
	q := &fakeQuerier{row: fakeRow{bodyFat: &pct}}
	got, err := UpsertWeightEntryPartial(context.Background(), q, 3, "2026-08-08", KeepWeight, BodyFatUpdate{Set: true, Value: &pct})
	if err != nil {
		t.Fatalf("UpsertWeightEntryPartial: %v", err)
	}
	if got.BodyFat == nil || *got.BodyFat != pct {
		t.Errorf("BodyFat = %v, want %v", got.BodyFat, pct)
	}
	if strings.Contains(q.sql, "INSERT") {
		t.Errorf("with no weight there is nothing to insert; got:\n%s", q.sql)
	}
	if !strings.Contains(q.sql, "UPDATE weight_entries") {
		t.Errorf("want an UPDATE; got:\n%s", q.sql)
	}
	if strings.Contains(q.sql, "SET weight") || strings.Contains(q.sql, "weight = ") {
		t.Errorf("the weight column must not be assigned; got:\n%s", q.sql)
	}
	for _, arg := range q.args {
		if w, ok := arg.(float64); ok {
			t.Errorf("a weight (%v) reached the statement despite KeepWeight", w)
		}
	}
	want := []any{3, "2026-08-08", true, &pct}
	if len(q.args) != len(want) {
		t.Fatalf("args = %v, want %v", q.args, want)
	}
	for i := range want {
		if fmt.Sprintf("%v", q.args[i]) != fmt.Sprintf("%v", want[i]) {
			t.Errorf("arg %d = %v, want %v", i, q.args[i], want[i])
		}
	}
}

func TestUpsertWeightEntryPartialKeepBothTouchesNeitherColumn(t *testing.T) {
	q := &fakeQuerier{row: fakeRow{}}
	if _, err := UpsertWeightEntryPartial(context.Background(), q, 3, "2026-08-08", KeepWeight, KeepBodyFat); err != nil {
		t.Fatalf("UpsertWeightEntryPartial: %v", err)
	}
	// $3 false makes the CASE fall through to the stored value, so even this
	// degenerate write cannot clear a reading.
	if len(q.args) < 3 || q.args[2] != false {
		t.Errorf("args = %v, want the body-fat Set flag to be false", q.args)
	}
}

func TestUpsertWeightEntryPartialKeepWeightNeedsAnExistingEntry(t *testing.T) {
	q := &fakeQuerier{row: fakeRow{err: pgx.ErrNoRows}}
	_, err := UpsertWeightEntryPartial(context.Background(), q, 3, "2026-08-08", KeepWeight, BodyFatUpdate{Set: true})
	if !errors.Is(err, ErrNoWeightEntry) {
		// Inventing a weight would be worse than refusing: the caller has to
		// be told there is nothing to attach the reading to.
		t.Errorf("err = %v, want ErrNoWeightEntry", err)
	}
}

func TestUpsertWeightEntryPartialSetWeightDoesNotMaskNoRows(t *testing.T) {
	// INSERT ... RETURNING always yields a row, so ErrNoRows on that path is a
	// real anomaly and must not be dressed up as "log a weight first".
	q := &fakeQuerier{row: fakeRow{err: pgx.ErrNoRows}}
	_, err := UpsertWeightEntryPartial(context.Background(), q, 3, "2026-08-08", SetWeight(82.0), KeepBodyFat)
	if errors.Is(err, ErrNoWeightEntry) {
		t.Errorf("err = %v, want the raw pgx.ErrNoRows", err)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("err = %v, want pgx.ErrNoRows", err)
	}
}

func TestWeightUpdateStates(t *testing.T) {
	if KeepWeight.Set {
		t.Error("KeepWeight.Set = true, want false")
	}
	got := SetWeight(82.5)
	if !got.Set || got.Value != 82.5 {
		t.Errorf("SetWeight(82.5) = %+v, want {Set:true Value:82.5}", got)
	}
}
