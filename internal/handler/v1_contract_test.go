package handler

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"schautrack/internal/model"
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
	if err := openapi.Build("", "").ValidateJSON(schemaName, raw); err != nil {
		t.Errorf("%v\n\nserialized as: %s", err, abbreviate(raw, 1500))
	}
}

// abbreviate keeps a failure's context readable. The error names the offending
// field; the payload is there to show what was actually sent, and a plan with a
// 160-week curve buries the useful part under kilobytes of it.
func abbreviate(raw []byte, max int) string {
	if len(raw) <= max {
		return string(raw)
	}
	return fmt.Sprintf("%s… (%d bytes total)", raw[:max], len(raw))
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
	me.Features = v1Features{
		BodyFat: true, Todos: true, Notes: true, Macros: true, AutoCalcCalories: true,
	}
	checkSchema(t, "Me", me)

	// A never-expiring token on an account with no goal or language set, and
	// every optional feature off — the shape a brand-new account takes, and the
	// one that would expose a features field wrongly declared non-boolean or
	// accidentally omitted by an `omitempty`.
	me.Token.ExpiresAt = nil
	me.User.DailyGoal = nil
	me.User.Language = nil
	me.Features = v1Features{}
	checkSchema(t, "Me", me)
}

// The features block is a documented contract of its own: a client that reads
// features.notes to decide whether to offer note editing needs every key to be
// present on every response, not just the ones that happen to be true. Marshal
// a zero v1Features and assert the exact key set.
func TestMeFeaturesAreAlwaysPresent(t *testing.T) {
	raw, err := json.Marshal(v1Features{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := []string{"body_fat", "todos", "notes", "macros", "auto_calc_calories"}
	if len(got) != len(want) {
		t.Errorf("features has %d keys, want %d: %s", len(got), len(want), raw)
	}
	for _, k := range want {
		v, present := got[k]
		if !present {
			t.Errorf("features.%s is missing when false — a client cannot tell it from an unknown feature", k)
			continue
		}
		if v != false {
			t.Errorf("features.%s = %v on a zero value, want false", k, v)
		}
	}

	// And the spec must declare exactly those, so neither side can grow a key
	// the other does not know about.
	spec := openapi.Build("", "").Components.Schemas["Me"].Properties["features"]
	if spec == nil {
		t.Fatal("the Me schema declares no features object")
	}
	for _, k := range want {
		if _, ok := spec.Properties[k]; !ok {
			t.Errorf("the spec's features object omits %q", k)
		}
		if !slices.Contains(spec.Required, k) {
			t.Errorf("the spec does not mark features.%s required, so a client may not rely on it", k)
		}
	}
	if len(spec.Properties) != len(want) {
		t.Errorf("the spec declares %d feature keys, the struct emits %d", len(spec.Properties), len(want))
	}
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

// planSeries is a weight history ending on fixedTime, with enough readings far
// enough apart for TrendAnalysis to fit a line rather than bail out.
func planSeries() []service.WeightPoint {
	day := func(n int) time.Time { return fixedTime.AddDate(0, 0, -n) }
	bodyFat := 24.5
	return []service.WeightPoint{
		{Date: day(28), Weight: 92.0},
		{Date: day(21), Weight: 91.1},
		{Date: day(14), Weight: 90.4, BodyFat: &bodyFat},
		{Date: day(7), Weight: 89.2},
		{Date: day(0), Weight: 88.4},
	}
}

func activeGoal() *model.WeightGoal {
	return &model.WeightGoal{
		ID: 3, UserID: 1, StartWeight: 92, StartDate: "2026-07-08",
		TargetWeight: 80, PaceMode: "rate", RateKgPerWeek: ptr(0.5),
		ActivityLevel: ptr("moderate"), Status: "active",
		CreatedAt: fixedTime, UpdatedAt: fixedTime,
	}
}

// TestPlanMatchesSchema is the one this file most needed and longest lacked.
// /plan carries the largest payload in the API and the one that changes most
// often, and until the Plan schema was written down it was documented as a
// free-form object — so it validated against anything, and three fields
// (composition, computed.bmrFormula, series[].bodyFat) shipped undocumented.
//
// The payload is assembled by service.AssemblePlan rather than written out as a
// literal here, deliberately: a literal only proves the schema matches the
// literal. Running the real assembler means renaming a json tag on any plan
// struct, or adding a field and not documenting it, fails this test.
func TestPlanMatchesSchema(t *testing.T) {
	full := service.PlanInputs{
		CurrentWeight:  ptr(88.4),
		CurrentBodyFat: &service.BodyFatReading{Date: "2026-07-22", WeightKg: 90.4, Pct: 24.5},
		HeightCm:       ptr(180.0),
		BirthYear:      ptr(1990),
		Sex:            ptr("male"),
		ActivityLevel:  ptr("moderate"),
		Goal:           activeGoal(),
		Series:         planSeries(),
		CurrentCalGoal: ptr(2100),
		Now:            fixedTime,
	}

	dateGoal := activeGoal()
	dateGoal.PaceMode, dateGoal.RateKgPerWeek, dateGoal.TargetDate = "date", nil, ptr("2027-02-01")

	// No sex: composition is still derived (it needs only a body-fat reading)
	// but carries no category, and the metrics are incomplete so there is no
	// budget. Every nullable field in one payload.
	noSex := full
	noSex.Sex, noSex.Goal = nil, nil

	// A pace this aggressive for this profile trips three of the four warning
	// codes at once: the budget lands under the floor, the rate exceeds 1% of
	// body weight, and the target is in the underweight BMI band.
	clamped := service.PlanInputs{
		CurrentWeight: ptr(55.0), HeightCm: ptr(160.0), BirthYear: ptr(1986),
		Sex: ptr("female"), ActivityLevel: ptr("sedentary"),
		Goal: &model.WeightGoal{
			ID: 4, UserID: 2, StartWeight: 55, StartDate: "2026-08-01",
			TargetWeight: 45, PaceMode: "rate", RateKgPerWeek: ptr(1.0),
			Status: "active", CreatedAt: fixedTime, UpdatedAt: fixedTime,
		},
		Series: planSeries(), Now: fixedTime,
	}

	// The fourth code, from the other direction: a gain goal whose target is in
	// the obese BMI band.
	gain := service.PlanInputs{
		CurrentWeight: ptr(60.0), HeightCm: ptr(160.0), BirthYear: ptr(1986),
		Sex: ptr("other"), ActivityLevel: ptr("very_active"),
		Goal: &model.WeightGoal{
			ID: 5, UserID: 3, StartWeight: 60, StartDate: "2026-08-01",
			TargetWeight: 90, PaceMode: "rate", RateKgPerWeek: ptr(0.25),
			Status: "active", CreatedAt: fixedTime, UpdatedAt: fixedTime,
		},
		Series: planSeries(), Now: fixedTime,
	}

	// A goal with no body metrics behind it: trend is computed, computed is not.
	goalOnly := service.PlanInputs{
		CurrentWeight: ptr(88.4), Goal: activeGoal(),
		Series: planSeries(), Now: fixedTime,
	}

	dated := full
	dated.Goal = dateGoal

	cases := map[string]service.PlanInputs{
		"everything populated":     full,
		"goal paced by date":       dated,
		"no sex, no goal":          noSex,
		"clamped budget":           clamped,
		"gain goal":                gain,
		"goal without metrics":     goalOnly,
		"nothing logged at all":    {Now: fixedTime},
		"metrics but no readings":  {HeightCm: ptr(180.0), BirthYear: ptr(1990), Sex: ptr("male"), ActivityLevel: ptr("moderate"), Now: fixedTime},
		"readings but no goal yet": {CurrentWeight: ptr(88.4), Series: planSeries(), Now: fixedTime},
	}

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			checkSchema(t, "Plan", service.AssemblePlan(in))
		})
	}

	// The handler converts every weight-valued field before writing. A field
	// the converter reaches but the schema does not describe would show up
	// here and nowhere else.
	t.Run("converted to pounds", func(t *testing.T) {
		resp := service.AssemblePlan(full)
		service.ConvertPlanResponseToDisplayUnit(&resp, "lb")
		checkSchema(t, "Plan", resp)
	})
}

// TestPlanWarningsAreDocumented pins the enum: every warning the assembler can
// emit must be one the schema lists, or a client switching on `code` hits a
// value the document never mentioned.
func TestPlanWarningsAreDocumented(t *testing.T) {
	doc := openapi.Build("", "")
	schema := doc.Components.Schemas["PlanWarning"]
	documented := map[string]bool{}
	for _, v := range schema.Properties["code"].Enum {
		documented[v.(string)] = true
	}

	// The codes the assembler can produce, from plan_assemble.go.
	for _, code := range []string{"budget_clamped", "aggressive_rate", "target_underweight", "target_obese"} {
		if !documented[code] {
			t.Errorf("warning code %q is emitted but not documented", code)
		}
	}
	if len(documented) != 4 {
		t.Errorf("the schema documents %d warning codes, the assembler emits 4", len(documented))
	}
}

// TestValidatorRejectsDrift proves the validator would actually fail — a
// contract test that cannot fail is worse than none, because it reads as
// coverage.
func TestValidatorRejectsDrift(t *testing.T) {
	doc := openapi.Build("", "")

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
		// Plan was exempt from all of the above until its schema was written
		// down; these are the three drifts that actually shipped, plus the
		// undeclared-key case the old additionalProperties waiver allowed.
		{"undocumented plan field", "PlanComputed", `{"bmr":1700,"tdee":2635,"budgetKcal":2085,"budgetClamped":false,"rateKgPerWeek":0.5,"etaWeeks":16.8,"etaDate":"2026-11-29","planCurve":[],"bmrFormula":"katch_mcardle","secretMultiplier":1.5}`},
		{"missing plan sub-object", "Plan", `{"metrics":{"heightCm":180,"birthYear":1990,"sex":"male","activityLevel":"moderate","complete":true}}`},
		{"renamed composition field", "BodyComposition", `{"date":"2026-07-22","bodyFatPercent":24.5,"leanMass":68.3,"fatMass":22.1,"category":"average"}`},
		{"unknown bmr formula", "PlanComputed", `{"bmr":1700,"tdee":2635,"budgetKcal":2085,"budgetClamped":false,"rateKgPerWeek":0.5,"etaWeeks":16.8,"etaDate":null,"planCurve":[],"bmrFormula":"harris_benedict"}`},
		{"nullable ref given a wrong object", "Plan", `{"metrics":{"heightCm":null,"birthYear":null,"sex":null,"activityLevel":null,"complete":false},"currentWeight":null,"bmi":null,"bmiCategory":null,"composition":{"date":"2026-07-22"},"healthyRange":null,"goal":null,"computed":null,"trend":null,"currentCalorieGoal":null,"series":[],"warnings":[],"disclaimer":"x"}`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := doc.ValidateJSON(c.schema, []byte(c.body)); err == nil {
				t.Errorf("validator accepted %s — it would not catch this drift", c.name)
			}
		})
	}
}

// TestValidatorAcceptsFreeForm checks the schemas that are still deliberately
// open are not rejected for carrying undeclared keys. Both relay a shape this
// API does not own — the AI model's answer and OpenFoodFacts' product record —
// so pinning their fields would document someone else's contract.
//
// Plan used to be on this list. It was not free-form by intent, only by
// omission, which is exactly why it drifted.
func TestValidatorAcceptsFreeForm(t *testing.T) {
	doc := openapi.Build("", "")
	for _, name := range []string{"Estimate", "BarcodeProduct"} {
		if err := doc.ValidateJSON(name, []byte(`{"whatever":[1,2,3],"nested":{"x":true}}`)); err != nil {
			t.Errorf("%s is documented as free-form but was rejected: %v", name, err)
		}
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
