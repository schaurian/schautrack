package handler

import (
	"encoding/json"
	"testing"
)

// TestOptionalDistinguishesAbsentFromNull is the regression test for a bug that
// shipped in the first cut of the PATCH handlers.
//
// They used `**int`, on the reasonable-sounding theory that an outer nil means
// "absent" and a non-nil pointer to a nil pointer means "explicit null".
// encoding/json does not work that way: it unmarshals an explicit `null` into a
// pointer by setting the pointer to nil, producing exactly the same value as an
// absent key. The result was that `{"protein_g": null}` — the documented way to
// clear a macro — was silently read as "no fields to update" and returned 400.
func TestOptionalDistinguishesAbsentFromNull(t *testing.T) {
	type body struct {
		A Optional[int]    `json:"a"`
		B Optional[string] `json:"b"`
	}

	tests := []struct {
		name     string
		input    string
		wantSet  bool
		wantNull bool
		wantVal  int
	}{
		{"absent", `{}`, false, false, 0},
		{"explicit null", `{"a": null}`, true, true, 0},
		{"present value", `{"a": 42}`, true, false, 42},
		{"present zero", `{"a": 0}`, true, false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got body
			if err := json.Unmarshal([]byte(tt.input), &got); err != nil {
				t.Fatalf("unmarshal %s: %v", tt.input, err)
			}
			if got.A.Set != tt.wantSet {
				t.Errorf("Set = %v, want %v", got.A.Set, tt.wantSet)
			}
			isNull := got.A.Value == nil
			if tt.wantSet && isNull != tt.wantNull {
				t.Errorf("null = %v, want %v", isNull, tt.wantNull)
			}
			if tt.wantSet && !tt.wantNull && *got.A.Value != tt.wantVal {
				t.Errorf("Value = %d, want %d", *got.A.Value, tt.wantVal)
			}
		})
	}
}

// TestOptionalLeavesSiblingsAbsent checks that setting one field does not mark
// the others as present — the property the PATCH handlers rely on to build a
// partial UPDATE.
func TestOptionalLeavesSiblingsAbsent(t *testing.T) {
	var got struct {
		A Optional[int] `json:"a"`
		B Optional[int] `json:"b"`
	}
	if err := json.Unmarshal([]byte(`{"a": 1}`), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.A.Set {
		t.Error("a should be set")
	}
	if got.B.Set {
		t.Error("b was not in the body but reports Set — a PATCH would clobber it")
	}
}

// TestEntryPatchThreeStates exercises the real PATCH struct, not just the
// generic type, so a future refactor back to **T fails here.
func TestEntryPatchThreeStates(t *testing.T) {
	var absent v1EntryPatch
	if err := json.Unmarshal([]byte(`{"calories": 100}`), &absent); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if absent.ProteinG.Set {
		t.Error("protein_g was absent but reports Set")
	}
	if absent.Name.Set {
		t.Error("name was absent but reports Set")
	}

	var cleared v1EntryPatch
	if err := json.Unmarshal([]byte(`{"protein_g": null, "name": null}`), &cleared); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !cleared.ProteinG.Set || cleared.ProteinG.Value != nil {
		t.Error(`{"protein_g": null} must read as present-and-null, so the macro is cleared`)
	}
	if !cleared.Name.Set || cleared.Name.Value != nil {
		t.Error(`{"name": null} must read as present-and-null, so the name is cleared`)
	}

	var set v1EntryPatch
	if err := json.Unmarshal([]byte(`{"protein_g": 30}`), &set); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !set.ProteinG.Set || set.ProteinG.Value == nil || *set.ProteinG.Value != 30 {
		t.Error("protein_g: 30 did not round-trip")
	}
}

// TestSavedFoodPatchThreeStates covers the same contract on saved foods.
func TestSavedFoodPatchThreeStates(t *testing.T) {
	var p v1SavedFoodPatch
	if err := json.Unmarshal([]byte(`{"emoji": null, "calories": 250}`), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !p.Emoji.Set || p.Emoji.Value != nil {
		t.Error("emoji: null must clear the emoji")
	}
	if !p.Calories.Set || p.Calories.Value == nil || *p.Calories.Value != 250 {
		t.Error("calories: 250 did not round-trip")
	}
	if p.FatG.Set {
		t.Error("fat_g was absent but reports Set")
	}
}

// TestTodoPatchThreeStates covers time_of_day, the todo field that can be
// cleared.
func TestTodoPatchThreeStates(t *testing.T) {
	var p v1TodoPatch
	if err := json.Unmarshal([]byte(`{"time_of_day": null}`), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !p.TimeOfDay.Set || p.TimeOfDay.Value != nil {
		t.Error("time_of_day: null must clear the time")
	}

	var q v1TodoPatch
	if err := json.Unmarshal([]byte(`{"name": "Walk"}`), &q); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if q.TimeOfDay.Set {
		t.Error("time_of_day was absent but reports Set — a PATCH would wipe the time")
	}
}
