package handler

import (
	"encoding/json"
	"testing"
	"time"
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

// TestParseBodyFatUpdateCoercionMatrix walks every JSON shape the body_fat key
// can arrive as, which is the #341 half of the #303 story: parseBodyFatUpdate
// used to coerce with fmt.Sprintf("%v", …) and then compare the result against
// the literal string "<nil>" to recover a null it had already destroyed.
//
// The sentinel was defensive rather than wrong here — the nil check above it
// caught the null first — so almost every row below asserts *unchanged*
// behaviour. The one that changes is the literal "<nil>": it used to clear the
// column and is now just an unparseable body fat, the same call #338 made for
// the entry amount and macros.
func TestParseBodyFatUpdateCoercionMatrix(t *testing.T) {
	const (
		keep  = "keep"  // absent key: leave any stored reading alone
		clear = "clear" // Set with no value: NULL the column
		set   = "set"   // Set with a value
		bad   = "bad"   // unusable: the caller answers 400
	)

	tests := []struct {
		name string
		body string
		want string
		val  float64
	}{
		{"key absent", `{"weight":"75.5"}`, keep, 0},
		{"empty body", `{}`, keep, 0},
		{"explicit null", `{"body_fat":null}`, clear, 0},
		{"empty string", `{"body_fat":""}`, clear, 0},
		{"whitespace only", `{"body_fat":"   "}`, clear, 0},
		{"tabs and newlines", `{"body_fat":"\t\n "}`, clear, 0},
		{"a normal numeric string", `{"body_fat":"24.3"}`, set, 24.3},
		{"a comma decimal", `{"body_fat":"24,3"}`, set, 24.3},
		{"a JSON number", `{"body_fat":24.3}`, set, 24.3},
		{"a whole JSON number", `{"body_fat":24}`, set, 24},
		{"a padded string is trimmed", `{"body_fat":"  24.3  "}`, set, 24.3},
		// The behaviour change. Under the sentinel these four characters
		// silently cleared the reading; now they are what they look like.
		{"literal <nil> is rejected, not silently cleared", `{"body_fat":"<nil>"}`, bad, 0},
		{"a word", `{"body_fat":"abc"}`, bad, 0},
		{"boolean true", `{"body_fat":true}`, bad, 0},
		{"boolean false", `{"body_fat":false}`, bad, 0},
		{"an object", `{"body_fat":{"a":1}}`, bad, 0},
		{"an array", `{"body_fat":[1,2]}`, bad, 0},
		{"an empty array", `{"body_fat":[]}`, bad, 0},
		{"zero is out of range", `{"body_fat":0}`, bad, 0},
		{"a negative reading", `{"body_fat":-5}`, bad, 0},
		{"an impossible reading", `{"body_fat":99}`, bad, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseBodyFatUpdate(decodeBody(t, tt.body))
			if tt.want == bad {
				if ok {
					t.Fatalf("accepted %s as {Set:%v Value:%v}, want a 400", tt.body, got.Set, got.Value)
				}
				return
			}
			if !ok {
				t.Fatalf("rejected %s, want %s", tt.body, tt.want)
			}
			switch tt.want {
			case keep:
				if got.Set {
					t.Errorf("Set = true, want false — an absent key must not touch the column")
				}
			case clear:
				if !got.Set || got.Value != nil {
					t.Errorf("got {Set:%v Value:%v}, want a clear", got.Set, got.Value)
				}
			case set:
				if !got.Set || got.Value == nil {
					t.Fatalf("got {Set:%v Value:%v}, want a set", got.Set, got.Value)
				}
				if *got.Value != tt.val {
					t.Errorf("Value = %v, want %v", *got.Value, tt.val)
				}
			}
		})
	}
}

// TestWeightUpsertDate pins the entry_date / date / today fallback chain that
// POST /weight/upsert runs a body through.
//
// It used to coerce each key with %v before testing the result for emptiness,
// so a JSON null arrived as "<nil>" and had to be compared against that
// sentinel to be recognised as absent. A caller sending the literal four
// characters therefore had the reading quietly filed under today; now the
// string survives, fails isValidDate in the handler, and earns a 400.
func TestWeightUpsertDate(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	const today = "2026-08-08"

	tests := []struct {
		name string
		body string
		want string
	}{
		{"entry_date wins", `{"entry_date":"2026-01-02","date":"2026-03-04"}`, "2026-01-02"},
		{"date is the fallback key", `{"date":"2026-03-04"}`, "2026-03-04"},
		{"both keys absent means today", `{"weight":"82"}`, today},
		{"empty body means today", `{}`, today},
		{"a null entry_date falls through to date", `{"entry_date":null,"date":"2026-03-04"}`, "2026-03-04"},
		{"a null entry_date with no date means today", `{"entry_date":null}`, today},
		{"an empty entry_date falls through to date", `{"entry_date":"","date":"2026-03-04"}`, "2026-03-04"},
		{"a whitespace entry_date falls through", `{"entry_date":"   ","date":"2026-03-04"}`, "2026-03-04"},
		{"both null means today", `{"entry_date":null,"date":null}`, today},
		{"a padded date is trimmed", `{"entry_date":"  2026-01-02  "}`, "2026-01-02"},
		// The behaviour change: these used to be swallowed by the sentinel and
		// silently become today. They now reach isValidDate and are rejected.
		{"literal <nil> is kept so the handler can reject it", `{"entry_date":"<nil>"}`, "<nil>"},
		// json.Unmarshal into any gives float64, so %v renders a large integer
		// in scientific notation. Unchanged from the pre-refactor coercion —
		// pinned here so nobody "fixes" it into something isValidDate accepts.
		{"a number is kept so the handler can reject it", `{"entry_date":20260102}`, "2.0260102e+07"},
		{"a small number is kept so the handler can reject it", `{"entry_date":5}`, "5"},
		{"a boolean is kept so the handler can reject it", `{"entry_date":true}`, "true"},
		{"an object is kept so the handler can reject it", `{"entry_date":{"a":1}}`, "map[a:1]"},
		{"an array is kept so the handler can reject it", `{"entry_date":[1,2]}`, "[1 2]"},
		{"a garbage string is kept so the handler can reject it", `{"entry_date":"not-a-date"}`, "not-a-date"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := weightUpsertDate(decodeBody(t, tt.body), now, "UTC"); got != tt.want {
				t.Errorf("weightUpsertDate(%s) = %q, want %q", tt.body, got, tt.want)
			}
		})
	}
}

// TestWeightUpsertDateRejectsWhatItPassesThrough is the other half of the
// change above: a value the sentinel used to swallow must not merely survive
// weightUpsertDate, it must actually fail the handler's date check, or all the
// refactor did is move a silent "today" one line later.
func TestWeightUpsertDateRejectsWhatItPassesThrough(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	for _, body := range []string{
		`{"entry_date":"<nil>"}`,
		`{"date":"<nil>"}`,
		`{"entry_date":true}`,
		`{"entry_date":{"a":1}}`,
		`{"entry_date":"not-a-date"}`,
	} {
		got := weightUpsertDate(decodeBody(t, body), now, "UTC")
		if isValidDate(got) {
			t.Errorf("%s resolved to %q, which isValidDate accepts — the reading would be filed under a bogus date", body, got)
		}
	}
}

// TestWeightUpsertDateUsesTheAccountTimezone guards the reason `now` is a
// parameter: "today" is today for the account, not for the server.
func TestWeightUpsertDateUsesTheAccountTimezone(t *testing.T) {
	// 23:30 UTC on the 8th is already the 9th in Auckland.
	now := time.Date(2026, 8, 8, 23, 30, 0, 0, time.UTC)
	if got := weightUpsertDate(decodeBody(t, `{}`), now, "UTC"); got != "2026-08-08" {
		t.Errorf("UTC: got %q, want 2026-08-08", got)
	}
	if got := weightUpsertDate(decodeBody(t, `{}`), now, "Pacific/Auckland"); got != "2026-08-09" {
		t.Errorf("Pacific/Auckland: got %q, want 2026-08-09", got)
	}
}
