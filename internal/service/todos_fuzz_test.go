package service

import (
	"bytes"
	"encoding/json"
	"testing"
)

// FuzzValidateSchedule drives the todo schedule validator with arbitrary
// decoded JSON.
//
// ValidateSchedule takes `any` — whatever encoding/json produced from a
// request body — so the fuzzer feeds it raw bytes through json.Unmarshal into
// `any`, exactly the way the handler reaches it. Anything that is not valid
// JSON never gets that far and is skipped.
//
// Properties asserted:
//
//   - never panics for any decoded JSON value;
//   - !Ok implies an Error message and no Schedule, so a rejection is never
//     silently stored;
//   - Ok implies the emitted Schedule is valid JSON that unmarshals into a
//     Schedule with a recognised type;
//   - Ok implies the emitted Schedule re-validates to itself — feeding the
//     stored form back through ValidateSchedule is a fixed point. This is what
//     makes an edit round-trip safe: the DB value is always accepted again.
func FuzzValidateSchedule(f *testing.F) {
	seeds := []string{
		// Accepted shapes.
		`{"type":"daily"}`,
		`{"type":"weekdays","days":[1,3,5]}`,
		`{"type":"weekdays","days":[7]}`,
		`{"type":"weekdays","days":[1,1,2]}`,
		// Rejected shapes from TestValidateSchedule.
		`{"type":"weekdays","days":[]}`,
		`{"type":"monthly"}`,
		`{}`,
		`null`,
		// Values that are not objects at all.
		`[]`, `"daily"`, `5`, `true`,
		// Out-of-range, wrong-typed and pathological day values.
		`{"type":"weekdays","days":[0,8,-1]}`,
		`{"type":"weekdays","days":["1",null,{},[]]}`,
		`{"type":"weekdays","days":[1.5,2.9]}`,
		`{"type":"weekdays","days":[1e309]}`,
		`{"type":"weekdays","days":[9223372036854775808]}`,
		`{"type":"weekdays","days":[-1e309]}`,
		`{"type":null}`,
		`{"type":"daily","days":[1]}`,
		`{"TYPE":"daily"}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		var decoded any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Skip() // not a JSON body; the handler never reaches the validator
		}

		got := ValidateSchedule(decoded)

		if !got.Ok {
			if got.Error == "" {
				t.Fatalf("ValidateSchedule(%s) rejected with an empty Error message", raw)
			}
			if len(got.Schedule) != 0 {
				t.Fatalf("ValidateSchedule(%s) rejected but emitted Schedule %s", raw, got.Schedule)
			}
			return
		}

		if len(got.Schedule) == 0 {
			t.Fatalf("ValidateSchedule(%s) = Ok with an empty Schedule", raw)
		}
		var s Schedule
		if err := json.Unmarshal(got.Schedule, &s); err != nil {
			t.Fatalf("ValidateSchedule(%s) emitted unparseable Schedule %s: %v", raw, got.Schedule, err)
		}
		switch s.Type {
		case "daily":
			if len(s.Days) != 0 {
				t.Fatalf("ValidateSchedule(%s) emitted a daily schedule carrying days %v", raw, s.Days)
			}
		case "weekdays":
			if len(s.Days) == 0 {
				t.Fatalf("ValidateSchedule(%s) emitted a weekdays schedule with no days", raw)
			}
			seen := map[int]bool{}
			for _, d := range s.Days {
				if d < 1 || d > 7 {
					t.Fatalf("ValidateSchedule(%s) emitted out-of-range ISO weekday %d", raw, d)
				}
				if seen[d] {
					t.Fatalf("ValidateSchedule(%s) emitted duplicate weekday %d in %v", raw, d, s.Days)
				}
				seen[d] = true
			}
		default:
			t.Fatalf("ValidateSchedule(%s) emitted unrecognised schedule type %q", raw, s.Type)
		}

		// Fixed point: what we store must validate again, byte for byte.
		var reDecoded any
		if err := json.Unmarshal(got.Schedule, &reDecoded); err != nil {
			t.Fatalf("emitted Schedule %s is not valid JSON: %v", got.Schedule, err)
		}
		again := ValidateSchedule(reDecoded)
		if !again.Ok {
			t.Fatalf("ValidateSchedule(%s) emitted %s, which does not re-validate: %s",
				raw, got.Schedule, again.Error)
		}
		if !bytes.Equal(again.Schedule, got.Schedule) {
			t.Fatalf("ValidateSchedule is not idempotent: %s -> %s -> %s",
				raw, got.Schedule, again.Schedule)
		}
	})
}
