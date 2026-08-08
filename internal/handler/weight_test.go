package handler

import (
	"encoding/json"
	"testing"
)

// decodeBody mirrors how the weight and entries handlers receive a request:
// json.Unmarshal into map[string]any, so numbers arrive as float64 and an
// explicit JSON null arrives as a present key holding nil.
func decodeBody(t *testing.T, raw string) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("bad test fixture %q: %v", raw, err)
	}
	return body
}

func TestParseBodyFatUpdate(t *testing.T) {
	t.Run("absent key preserves the stored reading", func(t *testing.T) {
		// The important case: a weight-only save from the dashboard, the
		// generic POST /entries, or an older client must not wipe a body-fat
		// reading taken on the same day.
		got, ok := parseBodyFatUpdate(decodeBody(t, `{"weight":"75.5"}`))
		if !ok {
			t.Fatal("expected a weight-only body to be accepted")
		}
		if got.Set {
			t.Errorf("Set = true for an absent body_fat key, want false (preserve)")
		}
		if got.Value != nil {
			t.Errorf("Value = %v, want nil", *got.Value)
		}
	})

	t.Run("explicit null clears the reading", func(t *testing.T) {
		got, ok := parseBodyFatUpdate(decodeBody(t, `{"weight":"75.5","body_fat":null}`))
		if !ok {
			t.Fatal("expected an explicit null to be accepted")
		}
		if !got.Set {
			t.Error("Set = false for an explicit null, want true (clear)")
		}
		if got.Value != nil {
			t.Errorf("Value = %v, want nil so the column is cleared", *got.Value)
		}
	})

	t.Run("empty string clears the reading", func(t *testing.T) {
		// What the UI sends when the user empties the input.
		got, ok := parseBodyFatUpdate(decodeBody(t, `{"body_fat":""}`))
		if !ok || !got.Set || got.Value != nil {
			t.Errorf("got {Set:%v Value:%v ok:%v}, want a clear", got.Set, got.Value, ok)
		}
	})

	t.Run("a number sets the reading", func(t *testing.T) {
		for _, raw := range []string{`{"body_fat":24.3}`, `{"body_fat":"24.3"}`, `{"body_fat":"24,3"}`} {
			got, ok := parseBodyFatUpdate(decodeBody(t, raw))
			if !ok {
				t.Errorf("%s: expected acceptance", raw)
				continue
			}
			if !got.Set || got.Value == nil {
				t.Errorf("%s: got {Set:%v Value:%v}, want a set", raw, got.Set, got.Value)
				continue
			}
			if *got.Value != 24.3 {
				t.Errorf("%s: Value = %v, want 24.3", raw, *got.Value)
			}
		}
	})

	t.Run("an unusable value is rejected rather than dropped", func(t *testing.T) {
		for _, raw := range []string{`{"body_fat":0}`, `{"body_fat":-5}`, `{"body_fat":99}`, `{"body_fat":"abc"}`} {
			if _, ok := parseBodyFatUpdate(decodeBody(t, raw)); ok {
				t.Errorf("%s: expected rejection so the caller can answer 400", raw)
			}
		}
	})
}

func TestParseWeightUpdate(t *testing.T) {
	t.Run("absent key preserves the stored weight", func(t *testing.T) {
		// The case the endpoint was missing: a body-fat-only save. Before
		// this, the dashboard had to restate its cached weight, which
		// overwrote a newer one logged from another device.
		got, ok := parseWeightUpdate(decodeBody(t, `{"body_fat":24.3}`))
		if !ok {
			t.Fatal("expected a body-fat-only body to be accepted")
		}
		if got.Set {
			t.Errorf("Set = true for an absent weight key, want false (preserve)")
		}
	})

	t.Run("null and empty string also preserve", func(t *testing.T) {
		for _, raw := range []string{`{"weight":null,"body_fat":24.3}`, `{"weight":"","body_fat":24.3}`, `{"weight":"   ","body_fat":24.3}`} {
			got, ok := parseWeightUpdate(decodeBody(t, raw))
			if !ok || got.Set {
				t.Errorf("%s: got {Set:%v ok:%v}, want a preserve", raw, got.Set, ok)
			}
		}
	})

	t.Run("a number sets the weight", func(t *testing.T) {
		for _, raw := range []string{`{"weight":82}`, `{"weight":"82"}`, `{"weight":"82,0"}`} {
			got, ok := parseWeightUpdate(decodeBody(t, raw))
			if !ok {
				t.Errorf("%s: expected acceptance", raw)
				continue
			}
			if !got.Set || got.Value != 82 {
				t.Errorf("%s: got {Set:%v Value:%v}, want {true 82}", raw, got.Set, got.Value)
			}
		}
	})

	t.Run("an unusable value is rejected rather than dropped", func(t *testing.T) {
		// Rejected, not treated as "preserve": silently ignoring a weight the
		// user did type would look like a successful save.
		for _, raw := range []string{`{"weight":0}`, `{"weight":-5}`, `{"weight":1501}`, `{"weight":"abc"}`} {
			if _, ok := parseWeightUpdate(decodeBody(t, raw)); ok {
				t.Errorf("%s: expected rejection so the caller can answer 400", raw)
			}
		}
	})
}
