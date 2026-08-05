package handler

import (
	"encoding/json"
	"testing"
	"time"

	"schautrack/internal/openapi"
	"schautrack/internal/service"
)

// The response structs are marshalled and checked against the schemas the
// published document declares.
//
// TestV1RoutesMatchSpec proves the route table and the spec agree on which
// endpoints exist. It says nothing about what they return — renaming a json tag
// on v1Entry would leave every test green while api/openapi.json went on
// describing a field the server no longer sends. This closes that hole.
//
// It needs no database on purpose: the thing that drifts is the Go struct, and
// marshalling one populated instance exercises exactly that. Wiring a DB in
// would buy coverage of the queries, which the handler tests already have, at
// the cost of a test nobody can run offline.

func ptr[T any](v T) *T { return &v }

var (
	fixedTime  = time.Date(2026, 8, 5, 7, 12, 0, 0, time.UTC)
	fullMacros = v1Macros{
		ProteinG: ptr(12), CarbsG: ptr(60), FatG: ptr(8),
		FiberG: ptr(5), SugarG: ptr(9),
	}
	// Every macro nil — the "not recorded" case, which must still satisfy the
	// schema because those fields are declared nullable AND required.
	emptyMacros = v1Macros{}
)

// checkSchema marshals v and validates the result against the named schema.
func checkSchema(t *testing.T, schemaName string, v any) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %s: %v", schemaName, err)
	}
	if err := openapi.Build("").ValidateJSON(schemaName, raw); err != nil {
		t.Errorf("%v\n\nserialized as: %s", err, raw)
	}
}

func TestEntryMatchesSchema(t *testing.T) {
	checkSchema(t, "Entry", v1Entry{
		ID: 1, Date: "2026-08-05", Calories: 450, Name: ptr("Porridge"),
		Macros: fullMacros, CreatedAt: fixedTime, LocalTime: "07:12",
	})
}

// A nameless entry with no macros recorded is the minimal real response, and
// the one most likely to expose a field wrongly marked non-nullable.
func TestEntryWithNullsMatchesSchema(t *testing.T) {
	checkSchema(t, "Entry", v1Entry{
		ID: 2, Date: "2026-08-05", Calories: 0, Name: nil,
		Macros: emptyMacros, CreatedAt: fixedTime, LocalTime: "07:12",
	})
}

func TestEntryListMatchesSchema(t *testing.T) {
	hasMore := true
	cursor := "MjAyNi0wOC0wNSwx"
	checkSchema(t, "EntryList", v1List[v1Entry]{
		Data: []v1Entry{{
			ID: 1, Date: "2026-08-05", Calories: 450, Name: ptr("Porridge"),
			Macros: fullMacros, CreatedAt: fixedTime, LocalTime: "07:12",
		}},
		HasMore: &hasMore, NextCursor: &cursor,
	})
}

// The last page omits next_cursor entirely; the schema must tolerate that.
func TestEntryListLastPageMatchesSchema(t *testing.T) {
	hasMore := false
	checkSchema(t, "EntryList", v1List[v1Entry]{Data: []v1Entry{}, HasMore: &hasMore})
}

func TestWeightMatchesSchema(t *testing.T) {
	checkSchema(t, "Weight", v1Weight{
		Date: "2026-08-05", Weight: 82.4, Unit: "kg",
		CreatedAt: fixedTime, UpdatedAt: fixedTime,
	})
	// lb is the other documented enum value; a typo in weightUnit() that let
	// through anything else would be caught here.
	checkSchema(t, "Weight", v1Weight{
		Date: "2026-08-05", Weight: 181.2, Unit: "lb",
		CreatedAt: fixedTime, UpdatedAt: fixedTime,
	})
}

func TestWeightListMatchesSchema(t *testing.T) {
	checkSchema(t, "WeightList", v1List[v1Weight]{Data: []v1Weight{{
		Date: "2026-08-05", Weight: 82.4, Unit: "kg",
		CreatedAt: fixedTime, UpdatedAt: fixedTime,
	}}})
}

func TestTodoMatchesSchema(t *testing.T) {
	checkSchema(t, "Todo", v1Todo{
		ID: 1, Name: "Walk the dog", Schedule: json.RawMessage(`{"type":"daily"}`),
		TimeOfDay: ptr("08:00"), SortOrder: 0, CreatedAt: fixedTime,
	})
	// An untimed todo.
	checkSchema(t, "Todo", v1Todo{
		ID: 2, Name: "Stretch", Schedule: json.RawMessage(`{"type":"weekly","days":[1,3,5]}`),
		TimeOfDay: nil, SortOrder: 1, CreatedAt: fixedTime,
	})
}

func TestTodoListMatchesSchema(t *testing.T) {
	checkSchema(t, "TodoList", v1List[v1Todo]{Data: []v1Todo{{
		ID: 1, Name: "Walk the dog", Schedule: json.RawMessage(`{"type":"daily"}`),
		TimeOfDay: ptr("08:00"), SortOrder: 0, CreatedAt: fixedTime,
	}}})
}

func TestTodoDayMatchesSchema(t *testing.T) {
	checkSchema(t, "TodoDay", v1TodoDay{
		ID: 1, Name: "Walk the dog", TimeOfDay: ptr("08:00"),
		Completed: true, Streak: 5, MissedSince: nil,
	})
	checkSchema(t, "TodoDay", v1TodoDay{
		ID: 1, Name: "Walk the dog", TimeOfDay: nil,
		Completed: false, Streak: 0, MissedSince: ptr("2026-08-01"),
	})
}

func TestTodoDayListMatchesSchema(t *testing.T) {
	checkSchema(t, "TodoDayList", v1List[v1TodoDay]{Data: []v1TodoDay{{
		ID: 1, Name: "Walk the dog", TimeOfDay: ptr("08:00"),
		Completed: true, Streak: 5,
	}}})
}

func TestSavedFoodMatchesSchema(t *testing.T) {
	checkSchema(t, "SavedFood", v1SavedFood{
		ID: 1, Name: "Banana", Emoji: ptr("🍌"), Calories: ptr(105),
		Macros: fullMacros, UseCount: 3, LastUsedAt: &fixedTime,
		CreatedAt: fixedTime, UpdatedAt: fixedTime,
	})
	// Never used, no emoji, no calorie value.
	checkSchema(t, "SavedFood", v1SavedFood{
		ID: 2, Name: "Water", Emoji: nil, Calories: nil,
		Macros: emptyMacros, UseCount: 0, LastUsedAt: nil,
		CreatedAt: fixedTime, UpdatedAt: fixedTime,
	})
}

func TestSavedFoodListMatchesSchema(t *testing.T) {
	checkSchema(t, "SavedFoodList", v1List[v1SavedFood]{Data: []v1SavedFood{{
		ID: 1, Name: "Banana", Emoji: ptr("🍌"), Calories: ptr(105),
		Macros: fullMacros, UseCount: 3, LastUsedAt: &fixedTime,
		CreatedAt: fixedTime, UpdatedAt: fixedTime,
	}}})
}

func TestNoteMatchesSchema(t *testing.T) {
	checkSchema(t, "Note", v1Note{Date: "2026-08-05", Content: "Felt good.", UpdatedAt: &fixedTime})
	// A day with no note: 200 with empty content and a null timestamp.
	checkSchema(t, "Note", v1Note{Date: "2026-08-05", Content: "", UpdatedAt: nil})
}

func TestMeMatchesSchema(t *testing.T) {
	var me v1Me
	me.User.ID = 1
	me.User.Email = "user@example.com"
	me.User.Timezone = "Europe/Berlin"
	me.User.WeightUnit = "kg"
	me.User.DailyGoal = ptr(2000)
	me.User.Language = ptr("en")
	me.Token.ID = 1
	me.Token.Name = "Home Assistant"
	me.Token.Prefix = "stk_a1b2c3"
	me.Token.Scopes = []string{"entries:read", "entries:write"}
	me.Token.ExpiresAt = &fixedTime
	me.Server.Version = "v2.4.0"
	me.Server.Today = "2026-08-05"
	checkSchema(t, "Me", me)

	// A never-expiring token on an account with no goal or language set.
	me.Token.ExpiresAt = nil
	me.User.DailyGoal = nil
	me.User.Language = nil
	checkSchema(t, "Me", me)
}

func TestCompletionMatchesSchema(t *testing.T) {
	checkSchema(t, "Completion", map[string]any{
		"todo_id": 1, "date": "2026-08-05", "completed": true,
	})
}

// The error format is what clients branch on, so it gets the same treatment.
func TestProblemMatchesSchema(t *testing.T) {
	checkSchema(t, "Problem", map[string]any{
		"type":     "https://schautrack.com/problems/validation-failed",
		"title":    "Validation failed",
		"status":   422,
		"detail":   "One or more macro values are out of range.",
		"instance": "/api/v1/entries",
		"invalid_params": []map[string]any{
			{"name": "protein_g", "reason": "must be between 0 and 999"},
		},
	})
	checkSchema(t, "Problem", map[string]any{
		"type":  "https://schautrack.com/problems/insufficient-scope",
		"title": "Insufficient scope", "status": 403,
		"required_scope": "entries:write",
	})
}

// TestValidatorRejectsDrift proves the validator would actually fail — a
// contract test that cannot fail is worse than none, because it reads as
// coverage.
func TestValidatorRejectsDrift(t *testing.T) {
	doc := openapi.Build("")

	cases := []struct {
		name, schema string
		body         string
	}{
		{"renamed field", "Entry", `{"id":1,"date":"2026-08-05","kcal":450,"name":null,"macros":{"protein_g":null,"carbs_g":null,"fat_g":null,"fiber_g":null,"sugar_g":null},"created_at":"2026-08-05T07:12:00Z","local_time":"07:12"}`},
		{"missing required field", "Entry", `{"id":1,"date":"2026-08-05","name":null,"macros":{"protein_g":null,"carbs_g":null,"fat_g":null,"fiber_g":null,"sugar_g":null},"created_at":"2026-08-05T07:12:00Z","local_time":"07:12"}`},
		{"wrong type", "Entry", `{"id":"one","date":"2026-08-05","calories":450,"name":null,"macros":{"protein_g":null,"carbs_g":null,"fat_g":null,"fiber_g":null,"sugar_g":null},"created_at":"2026-08-05T07:12:00Z","local_time":"07:12"}`},
		{"undocumented extra field", "Note", `{"date":"2026-08-05","content":"x","updated_at":null,"secret_internal_flag":true}`},
		{"null in a non-nullable field", "Note", `{"date":null,"content":"x","updated_at":null}`},
		{"value outside the enum", "Weight", `{"date":"2026-08-05","weight":80,"unit":"stone","created_at":"2026-08-05T07:12:00Z","updated_at":"2026-08-05T07:12:00Z"}`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := doc.ValidateJSON(c.schema, []byte(c.body)); err == nil {
				t.Errorf("validator accepted %s — it would not catch this drift", c.name)
			}
		})
	}
}

// TestValidatorAcceptsFreeForm checks the deliberately open Plan schema is not
// rejected for carrying undeclared keys.
func TestValidatorAcceptsFreeForm(t *testing.T) {
	doc := openapi.Build("")
	if err := doc.ValidateJSON("Plan", []byte(`{"metrics":{"heightCm":180},"anything":[1,2,3]}`)); err != nil {
		t.Errorf("Plan is documented as free-form but was rejected: %v", err)
	}
}

func TestLinkMatchesSchema(t *testing.T) {
	all := map[string]bool{"nutrition": true, "weight": true, "todos": true, "notes": true}
	none := map[string]bool{"nutrition": false, "weight": false, "todos": false, "notes": false}
	checkSchema(t, "Link", v1Link{
		UserID: 7, Email: "friend@example.com", Label: ptr("Alex"),
		SharesWithMe: all, SharesToThem: none, Timezone: "Europe/Berlin",
	})
	// An unlabelled link sharing nothing — the shape a pending-but-accepted
	// link with all categories off takes.
	checkSchema(t, "Link", v1Link{
		UserID: 8, Email: "other@example.com", Label: nil,
		SharesWithMe: none, SharesToThem: none, Timezone: "UTC",
	})
}

func TestLinkListMatchesSchema(t *testing.T) {
	all := map[string]bool{"nutrition": true, "weight": true, "todos": true, "notes": true}
	checkSchema(t, "LinkList", v1List[v1Link]{Data: []v1Link{{
		UserID: 7, Email: "friend@example.com", Label: ptr("Alex"),
		SharesWithMe: all, SharesToThem: all, Timezone: "Europe/Berlin",
	}}})
}

// decodeShareFlags must always emit exactly the four known categories: a
// response that omitted one would read as "not shared" to a client that
// checks for the key, and one that invented a category would be undocumented
// surface.
func TestDecodeShareFlagsIsTotal(t *testing.T) {
	cases := map[string]string{
		"empty":              ``,
		"null":               `null`,
		"partial":            `{"weight":true}`,
		"unknown categories": `{"weight":true,"telepathy":true}`,
		"all":                `{"nutrition":true,"weight":true,"todos":true,"notes":true}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			got := decodeShareFlags([]byte(raw))
			if len(got) != 4 {
				t.Errorf("got %d categories, want exactly 4: %v", len(got), got)
			}
			for _, c := range []string{"nutrition", "weight", "todos", "notes"} {
				if _, ok := got[c]; !ok {
					t.Errorf("category %q missing", c)
				}
			}
			if _, ok := got["telepathy"]; ok {
				t.Error("an unknown category leaked into the response")
			}
		})
	}
}

// TestAIScopeIsNotImplied is the money guard, asserted rather than assumed.
// If ai:estimate ever became implied by another scope, a token minted to log
// breakfast could quietly run up the operator's AI bill.
func TestAIScopeIsNotImplied(t *testing.T) {
	for _, granted := range service.AllScopes() {
		if granted == service.ScopeAIEstimate {
			continue
		}
		if service.ScopeSatisfies([]string{granted}, service.ScopeAIEstimate) {
			t.Errorf("scope %q implies %q — it must be granted deliberately and alone",
				granted, service.ScopeAIEstimate)
		}
	}
}

// Settings writes must not be reachable from a read-only token.
func TestSettingsWriteIsNotImpliedByReads(t *testing.T) {
	readOnly := []string{
		service.ScopeEntriesRead, service.ScopeWeightRead, service.ScopeTodosRead,
		service.ScopeFoodsRead, service.ScopeNotesRead, service.ScopePlanRead,
		service.ScopeLinksRead, service.ScopeSettingsRead,
	}
	for _, s := range readOnly {
		if service.ScopeSatisfies([]string{s}, service.ScopeSettingsWrite) {
			t.Errorf("read scope %q implies settings:write", s)
		}
	}
}
