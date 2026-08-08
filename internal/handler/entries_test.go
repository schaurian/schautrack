package handler

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"schautrack/internal/service"
)

func TestSanitizeDateRange(t *testing.T) {
	tests := []struct {
		name      string
		start     string
		end       string
		fallback  int
		wantStart string
		wantEnd   string
	}{
		{
			"fallback range with explicit end",
			"", "2025-03-15", 14,
			"2025-03-02", "2025-03-15",
		},
		{
			"clamps start to end when start > end",
			"2025-04-01", "2025-03-15", 14,
			"2025-03-15", "2025-03-15",
		},
		{
			"respects explicit start and end",
			"2025-03-01", "2025-03-10", 14,
			"2025-03-01", "2025-03-10",
		},
		{
			"clamps start to max lookback",
			"2020-01-01", "2025-03-15", 14,
			"2024-09-17", "2025-03-15",
		},
		{
			"month boundaries",
			"", "2025-03-01", 2,
			"2025-02-28", "2025-03-01",
		},
		{
			"leap year",
			"", "2024-03-01", 2,
			"2024-02-29", "2024-03-01",
		},
		{
			"year boundaries",
			"", "2025-01-01", 3,
			"2024-12-30", "2025-01-01",
		},
		{
			"ignores malformed start",
			"not-a-date", "2025-03-15", 7,
			"2025-03-09", "2025-03-15",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end := sanitizeDateRange(tt.start, tt.end, tt.fallback, "UTC")
			if start != tt.wantStart {
				t.Errorf("start = %q, want %q", start, tt.wantStart)
			}
			if end != tt.wantEnd {
				t.Errorf("end = %q, want %q", end, tt.wantEnd)
			}
		})
	}
}

func TestSanitizeDateRangeFutureEnd(t *testing.T) {
	_, end := sanitizeDateRange("", "2099-12-31", 7, "UTC")
	if end == "2099-12-31" {
		t.Error("future end date should be clamped to today")
	}
}

func TestDateReValidation(t *testing.T) {
	valid := []string{
		"2025-01-01",
		"2024-12-31",
		"2000-06-15",
		"1999-01-01",
	}
	for _, d := range valid {
		if !dateRe.MatchString(d) {
			t.Errorf("dateRe should match %q", d)
		}
	}

	invalid := []string{
		"",
		"2025-1-1",
		"2025/01/01",
		"01-01-2025",
		"not-a-date",
		"2025-01-01T00:00:00Z",
		// Note: dateRe only validates format (YYYY-MM-DD), not semantic validity
		// "2025-13-01" would match the regex pattern - that's expected behavior
		" 2025-01-01",
		"2025-01-01 ",
	}
	for _, d := range invalid {
		if dateRe.MatchString(d) {
			t.Errorf("dateRe should NOT match %q", d)
		}
	}
}

func TestBuildMacroMap(t *testing.T) {
	p := func(n int) *int { return &n }

	tests := []struct {
		name    string
		enabled []string
		protein *int
		carbs   *int
		fat     *int
		fiber   *int
		sugar   *int
		wantNil bool
		wantLen int
	}{
		{"no enabled macros", nil, p(10), p(20), p(30), nil, nil, true, 0},
		{"empty enabled macros", []string{}, p(10), p(20), p(30), nil, nil, true, 0},
		{"protein only", []string{"protein"}, p(25), p(50), p(10), nil, nil, false, 1},
		{"multiple macros", []string{"protein", "carbs", "fat"}, p(25), p(50), p(10), nil, nil, false, 3},
		{"all macros", []string{"protein", "carbs", "fat", "fiber", "sugar"}, p(25), p(50), p(10), p(5), p(15), false, 5},
		{"nil values included", []string{"protein", "carbs"}, nil, nil, nil, nil, nil, false, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildMacroMap(tt.enabled, tt.protein, tt.carbs, tt.fat, tt.fiber, tt.sugar)
			if tt.wantNil {
				if got != nil {
					t.Errorf("buildMacroMap() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("buildMacroMap() = nil, want non-nil")
			}
			if len(got) != tt.wantLen {
				t.Errorf("buildMacroMap() has %d keys, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestBuildMacroMapValues(t *testing.T) {
	p := func(n int) *int { return &n }
	got := buildMacroMap([]string{"protein", "fat"}, p(25), p(50), p(10), nil, nil)
	if got == nil {
		t.Fatal("buildMacroMap() = nil, want non-nil")
	}
	if v, ok := got["protein"]; !ok || v == nil || *(v.(*int)) != 25 {
		t.Errorf("protein = %v, want 25", got["protein"])
	}
	if v, ok := got["fat"]; !ok || v == nil || *(v.(*int)) != 10 {
		t.Errorf("fat = %v, want 10", got["fat"])
	}
	if _, ok := got["carbs"]; ok {
		t.Error("carbs should not be present when not in enabledMacros")
	}
}

func TestBuildDailyStats(t *testing.T) {
	g := func(n int) *int { return &n }

	t.Run("no goal returns none status", func(t *testing.T) {
		stats := buildDailyStats(
			[]string{"2025-03-15"},
			map[string]int{"2025-03-15": 1500},
			nil, nil, nil, nil, nil, 10,
		)
		if len(stats) != 1 {
			t.Fatalf("got %d stats, want 1", len(stats))
		}
		if stats[0].Status != "none" {
			t.Errorf("status = %q, want \"none\"", stats[0].Status)
		}
		if stats[0].Total != 1500 {
			t.Errorf("total = %d, want 1500", stats[0].Total)
		}
	})

	t.Run("under goal returns under", func(t *testing.T) {
		stats := buildDailyStats(
			[]string{"2025-03-15"},
			map[string]int{"2025-03-15": 1500},
			g(2000), nil, nil, nil, nil, 10,
		)
		if stats[0].Status != "under" {
			t.Errorf("status = %q, want \"under\"", stats[0].Status)
		}
	})

	t.Run("over goal within threshold returns over", func(t *testing.T) {
		stats := buildDailyStats(
			[]string{"2025-03-15"},
			map[string]int{"2025-03-15": 2100},
			g(2000), nil, nil, nil, nil, 10,
		)
		if stats[0].Status != "over" {
			t.Errorf("status = %q, want \"over\"", stats[0].Status)
		}
	})

	t.Run("over goal beyond threshold returns over_threshold", func(t *testing.T) {
		stats := buildDailyStats(
			[]string{"2025-03-15"},
			map[string]int{"2025-03-15": 2201},
			g(2000), nil, nil, nil, nil, 10,
		)
		if stats[0].Status != "over_threshold" {
			t.Errorf("status = %q, want \"over_threshold\"", stats[0].Status)
		}
		if !stats[0].OverThreshold {
			t.Error("OverThreshold should be true")
		}
	})

	t.Run("no entries with goal returns zero", func(t *testing.T) {
		stats := buildDailyStats(
			[]string{"2025-03-15"},
			map[string]int{},
			g(2000), nil, nil, nil, nil, 10,
		)
		if stats[0].Status != "zero" {
			t.Errorf("status = %q, want \"zero\"", stats[0].Status)
		}
	})

	t.Run("multiple days", func(t *testing.T) {
		days := []string{"2025-03-15", "2025-03-14", "2025-03-13"}
		totals := map[string]int{
			"2025-03-15": 1500,
			"2025-03-14": 2100,
		}
		stats := buildDailyStats(days, totals, g(2000), nil, nil, nil, nil, 10)
		if len(stats) != 3 {
			t.Fatalf("got %d stats, want 3", len(stats))
		}
		if stats[0].Date != "2025-03-15" {
			t.Errorf("stats[0].Date = %q, want \"2025-03-15\"", stats[0].Date)
		}
		if stats[2].Status != "zero" {
			t.Errorf("day with no entries status = %q, want \"zero\"", stats[2].Status)
		}
	})

	t.Run("with macro goals worst status wins", func(t *testing.T) {
		stats := buildDailyStats(
			[]string{"2025-03-15"},
			map[string]int{"2025-03-15": 1500},
			g(2000),
			[]string{"protein"},
			map[string]int{"protein": 150},
			map[string]string{"protein": "target"},
			map[string]map[string]int{"2025-03-15": {"protein": 50}},
			10,
		)
		// Calories under goal = "under", protein 50/150 target = "danger" -> "over_threshold"
		// WorstDotStatus picks over_threshold
		if stats[0].Status != "over_threshold" {
			t.Errorf("status = %q, want \"over_threshold\"", stats[0].Status)
		}
	})
}

// Verify that the constants are sane
func TestEntryConstants(t *testing.T) {
	if MaxHistoryDays <= 0 {
		t.Errorf("MaxHistoryDays = %d, want > 0", MaxHistoryDays)
	}
	if DefaultRangeDays <= 0 || DefaultRangeDays > MaxHistoryDays {
		t.Errorf("DefaultRangeDays = %d, want > 0 and <= %d", DefaultRangeDays, MaxHistoryDays)
	}
	if MaxEntryCalories <= 0 {
		t.Errorf("MaxEntryCalories = %d, want > 0", MaxEntryCalories)
	}
	if MaxEntryMacro <= 0 {
		t.Errorf("MaxEntryMacro = %d, want > 0", MaxEntryMacro)
	}
}

// Ensure service utility functions work as expected (cross-package sanity)
func TestSubtractDaysUTC(t *testing.T) {
	tests := []struct {
		date string
		days int
		want string
	}{
		{"2025-03-15", 0, "2025-03-15"},
		{"2025-03-15", 7, "2025-03-08"},
		{"2025-03-01", 1, "2025-02-28"},
		{"2025-01-01", 1, "2024-12-31"},
		{"invalid", 5, "invalid"},
	}
	for _, tt := range tests {
		got := service.SubtractDaysUTC(tt.date, tt.days)
		if got != tt.want {
			t.Errorf("SubtractDaysUTC(%q, %d) = %q, want %q", tt.date, tt.days, got, tt.want)
		}
	}
}

func TestBuildDayOptionsBetween(t *testing.T) {
	days := service.BuildDayOptionsBetween("2025-03-13", "2025-03-15", 100)
	if len(days) != 3 {
		t.Fatalf("got %d days, want 3", len(days))
	}
	// Should be in reverse order (end first)
	if days[0] != "2025-03-15" || days[1] != "2025-03-14" || days[2] != "2025-03-13" {
		t.Errorf("days = %v, want [2025-03-15 2025-03-14 2025-03-13]", days)
	}
}

func TestBuildDayOptionsBetweenMaxDays(t *testing.T) {
	days := service.BuildDayOptionsBetween("2025-03-01", "2025-03-15", 3)
	if len(days) != 3 {
		t.Fatalf("got %d days, want 3 (capped by maxDays)", len(days))
	}
}

func TestBuildDayOptionsBetweenInvalid(t *testing.T) {
	days := service.BuildDayOptionsBetween("invalid", "2025-03-15", 10)
	if days != nil {
		t.Errorf("expected nil for invalid start date, got %v", days)
	}
}

// --- optionalString / optionalEntryName / buildEntryUpdates ---------------
//
// Regression coverage for #303. The legacy SPA surface decodes request bodies
// into map[string]any and used to coerce every value with fmt.Sprintf("%v", …)
// before inspecting it, which renders a JSON null as the four-character string
// "<nil>". Two of the three coercion sites in entries_crud.go then compared
// against that "<nil>" sentinel to recover "this was null"; the entry-name site
// did not, so POST /entries/:id/update with {"name": null} renamed the entry to
// <nil> instead of clearing it. The v1 surface never had the bug because
// Optional[T] keeps the three states apart in the type system
// (v1_optional_test.go); these tests are the map[string]any equivalent.

// TestOptionalString covers the coercion matrix: which JSON shapes are absent,
// which are null, and what a present value coerces to.
func TestOptionalString(t *testing.T) {
	// 118 ASCII bytes then a 4-byte avocado: 122 bytes total, so a 120-byte
	// cap lands two bytes inside the emoji. optionalString does no truncating,
	// so it must come back whole; TestOptionalEntryName checks the cut.
	longUTF8 := strings.Repeat("a", 118) + "🥑"

	tests := []struct {
		name        string
		body        string
		key         string
		wantPresent bool
		wantNil     bool
		wantValue   string
	}{
		{"key absent", `{"other":"x"}`, "name", false, true, ""},
		{"empty body", `{}`, "name", false, true, ""},
		{"explicit null", `{"name":null}`, "name", true, true, ""},
		{"empty string", `{"name":""}`, "name", true, false, ""},
		{"whitespace only", `{"name":"   "}`, "name", true, false, ""},
		{"tabs and newlines", `{"name":"\t\n "}`, "name", true, false, ""},
		{"normal string", `{"name":"Porridge"}`, "name", true, false, "Porridge"},
		{"string is trimmed", `{"name":"  Porridge  "}`, "name", true, false, "Porridge"},
		// The bug's mirror image: a user who legitimately types <nil> gets
		// those four characters stored, not a cleared field. Under the old
		// sentinel comparison this was indistinguishable from null.
		{"literal <nil> string", `{"name":"<nil>"}`, "name", true, false, "<nil>"},
		{"integer number", `{"name":42}`, "name", true, false, "42"},
		{"fractional number", `{"name":42.5}`, "name", true, false, "42.5"},
		{"negative number", `{"name":-7}`, "name", true, false, "-7"},
		{"zero", `{"name":0}`, "name", true, false, "0"},
		{"boolean true", `{"name":true}`, "name", true, false, "true"},
		{"boolean false", `{"name":false}`, "name", true, false, "false"},
		{"object", `{"name":{"a":1}}`, "name", true, false, "map[a:1]"},
		{"empty object", `{"name":{}}`, "name", true, false, "map[]"},
		{"array", `{"name":[1,2]}`, "name", true, false, "[1 2]"},
		{"empty array", `{"name":[]}`, "name", true, false, "[]"},
		{"over-120-byte string is not truncated here", `{"name":"` + longUTF8 + `"}`, "name", true, false, longUTF8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, present := optionalString(decodeBody(t, tt.body), tt.key)
			if present != tt.wantPresent {
				t.Fatalf("present = %v, want %v", present, tt.wantPresent)
			}
			if (got == nil) != tt.wantNil {
				t.Fatalf("value nil = %v, want %v (got %v)", got == nil, tt.wantNil, got)
			}
			if got != nil && *got != tt.wantValue {
				t.Errorf("value = %q, want %q", *got, tt.wantValue)
			}
		})
	}
}

// TestOptionalEntryName checks the entry-name layer: the 120-byte cap, the
// UTF-8 boundary walk-back, and the collapse of a blank value to nil so the
// column is cleared rather than set to "".
func TestOptionalEntryName(t *testing.T) {
	ascii130 := strings.Repeat("b", 130)
	// 118 'a' + 🥑 = 122 bytes; cutting at 120 lands mid-emoji, so
	// truncateUTF8 must walk back to 118 and drop the emoji entirely.
	utf8Boundary := strings.Repeat("a", 118) + "🥑"

	tests := []struct {
		name        string
		body        string
		wantPresent bool
		wantNil     bool
		wantValue   string
	}{
		{"key absent leaves the name alone", `{"amount":100}`, false, true, ""},
		{"explicit null clears the name", `{"name":null}`, true, true, ""},
		{"empty string clears the name", `{"name":""}`, true, true, ""},
		{"whitespace clears the name", `{"name":"   "}`, true, true, ""},
		{"a value sets the name", `{"name":"Porridge"}`, true, false, "Porridge"},
		{"literal <nil> is a real name", `{"name":"<nil>"}`, true, false, "<nil>"},
		{"a number becomes its text", `{"name":42}`, true, false, "42"},
		{"long ASCII is capped at 120 bytes", `{"name":"` + ascii130 + `"}`, true, false, strings.Repeat("b", 120)},
		{"cap walks back off a split rune", `{"name":"` + utf8Boundary + `"}`, true, false, strings.Repeat("a", 118)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, present := optionalEntryName(decodeBody(t, tt.body), "name")
			if present != tt.wantPresent {
				t.Fatalf("present = %v, want %v", present, tt.wantPresent)
			}
			if (got == nil) != tt.wantNil {
				t.Fatalf("value nil = %v, want %v (got %v)", got == nil, tt.wantNil, got)
			}
			if got == nil {
				return
			}
			if *got != tt.wantValue {
				t.Errorf("value = %q (%d bytes), want %q (%d bytes)", *got, len(*got), tt.wantValue, len(tt.wantValue))
			}
			if len(*got) > MaxEntryNameBytes {
				t.Errorf("value is %d bytes, over the %d-byte cap", len(*got), MaxEntryNameBytes)
			}
			if !utf8.ValidString(*got) {
				t.Errorf("value %q is not valid UTF-8; Postgres would reject it (22021)", *got)
			}
		})
	}
}

// TestBuildEntryUpdatesNameThreeStates is the #303 regression proper: it walks
// the same absent / null / present matrix TestEntryPatchThreeStates walks on
// the v1 surface, but through the map[string]any path POST /entries/:id/update
// actually takes.
func TestBuildEntryUpdatesNameThreeStates(t *testing.T) {
	t.Run("absent leaves the column alone", func(t *testing.T) {
		updates, values, msg := buildEntryUpdates(decodeBody(t, `{"amount":"250"}`), false)
		if msg != "" {
			t.Fatalf("unexpected rejection: %s", msg)
		}
		for _, u := range updates {
			if strings.HasPrefix(u, "entry_name") {
				t.Fatalf("entry_name in SET clause %v for a body that never mentioned it", updates)
			}
		}
		if len(values) != 1 {
			t.Fatalf("values = %v, want just the amount", values)
		}
	})

	t.Run("null clears the column", func(t *testing.T) {
		updates, values, msg := buildEntryUpdates(decodeBody(t, `{"name":null}`), false)
		if msg != "" {
			t.Fatalf("unexpected rejection: %s", msg)
		}
		if len(updates) != 1 || updates[0] != "entry_name = $1" {
			t.Fatalf("updates = %v, want [entry_name = $1]", updates)
		}
		if len(values) != 1 {
			t.Fatalf("values = %v, want one", values)
		}
		// The bug: this used to be a *string pointing at "<nil>", so the
		// entry was renamed to <nil> instead of having its name cleared.
		got, _ := values[0].(*string)
		if got != nil {
			t.Errorf("bound value = %q, want NULL — {\"name\": null} must clear the name, not rename the entry", *got)
		}
	})

	t.Run("a value sets the column", func(t *testing.T) {
		_, values, msg := buildEntryUpdates(decodeBody(t, `{"name":"  Porridge  "}`), false)
		if msg != "" {
			t.Fatalf("unexpected rejection: %s", msg)
		}
		got, _ := values[0].(*string)
		if got == nil || *got != "Porridge" {
			t.Errorf("bound value = %v, want a pointer to \"Porridge\"", got)
		}
	})

	t.Run("an empty string clears the column", func(t *testing.T) {
		// What the SPA sends when the user empties the inline name input.
		_, values, msg := buildEntryUpdates(decodeBody(t, `{"name":""}`), false)
		if msg != "" {
			t.Fatalf("unexpected rejection: %s", msg)
		}
		if got, _ := values[0].(*string); got != nil {
			t.Errorf("bound value = %q, want NULL", *got)
		}
	})

	t.Run("a literal <nil> is stored verbatim", func(t *testing.T) {
		_, values, msg := buildEntryUpdates(decodeBody(t, `{"name":"<nil>"}`), false)
		if msg != "" {
			t.Fatalf("unexpected rejection: %s", msg)
		}
		got, _ := values[0].(*string)
		if got == nil || *got != "<nil>" {
			t.Errorf("bound value = %v, want a pointer to \"<nil>\" — a user may legitimately name an entry that", got)
		}
	})
}

// TestBuildEntryUpdatesAmount pins the amount column's three states. amount is
// NOT NULL, so "cleared" means 0 rather than NULL.
func TestBuildEntryUpdatesAmount(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		autoCalc  bool
		wantSet   bool
		wantValue int
		wantMsg   bool
	}{
		{"absent leaves the column alone", `{"name":"x"}`, false, false, 0, false},
		{"null zeroes it", `{"amount":null}`, false, true, 0, false},
		{"empty string zeroes it", `{"amount":""}`, false, true, 0, false},
		{"explicit zero zeroes it", `{"amount":"0"}`, false, true, 0, false},
		{"a string value sets it", `{"amount":"250"}`, false, true, 250, false},
		{"a number value sets it", `{"amount":250}`, false, true, 250, false},
		{"an expression is evaluated", `{"amount":"100+150"}`, false, true, 250, false},
		{"garbage is rejected", `{"amount":"abc"}`, false, false, 0, true},
		// Previously "<nil>" was a magic zero. Now it is what it looks like:
		// an unparseable amount, and the caller gets a 400 instead of a
		// silent overwrite with 0.
		{"literal <nil> is rejected, not silently zeroed", `{"amount":"<nil>"}`, false, false, 0, true},
		{"over the cap is rejected", `{"amount":"99999"}`, false, false, 0, true},
		{"auto-calc ignores the field", `{"amount":"250"}`, true, false, 0, false},
		{"auto-calc ignores a null too", `{"amount":null}`, true, false, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updates, values, msg := buildEntryUpdates(decodeBody(t, tt.body), tt.autoCalc)
			if (msg != "") != tt.wantMsg {
				t.Fatalf("message = %q, wantMsg = %v", msg, tt.wantMsg)
			}
			if tt.wantMsg {
				return
			}
			idx := -1
			for i, u := range updates {
				if strings.HasPrefix(u, "amount") {
					idx = i
				}
			}
			if (idx >= 0) != tt.wantSet {
				t.Fatalf("updates = %v, wantSet = %v", updates, tt.wantSet)
			}
			if !tt.wantSet {
				return
			}
			if got, ok := values[idx].(int); !ok || got != tt.wantValue {
				t.Errorf("bound value = %v, want %d", values[idx], tt.wantValue)
			}
		})
	}
}

// TestBuildEntryUpdatesMacros pins the macro columns. Unlike amount these are
// nullable, and 0 means "clear" rather than "zero grams" — a deliberate legacy
// quirk of this surface, preserved here so a refactor cannot drop it silently.
func TestBuildEntryUpdatesMacros(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantSet   bool
		wantNull  bool
		wantValue int
		wantMsg   bool
	}{
		{"absent leaves the column alone", `{"name":"x"}`, false, false, 0, false},
		{"null clears it", `{"protein_g":null}`, true, true, 0, false},
		{"empty string clears it", `{"protein_g":""}`, true, true, 0, false},
		{"whitespace clears it", `{"protein_g":"   "}`, true, true, 0, false},
		{"zero clears it", `{"protein_g":"0"}`, true, true, 0, false},
		{"a string value sets it", `{"protein_g":"30"}`, true, false, 30, false},
		{"a number value sets it", `{"protein_g":30}`, true, false, 30, false},
		{"literal <nil> is rejected, not silently cleared", `{"protein_g":"<nil>"}`, false, false, 0, true},
		{"a negative value is rejected", `{"protein_g":"-1"}`, false, false, 0, true},
		{"over the cap is rejected", `{"protein_g":"1000"}`, false, false, 0, true},
		{"a non-integer is rejected", `{"protein_g":"abc"}`, false, false, 0, true},
		{"a fractional number is rejected", `{"protein_g":30.5}`, false, false, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updates, values, msg := buildEntryUpdates(decodeBody(t, tt.body), false)
			if (msg != "") != tt.wantMsg {
				t.Fatalf("message = %q, wantMsg = %v", msg, tt.wantMsg)
			}
			if tt.wantMsg {
				return
			}
			idx := -1
			for i, u := range updates {
				if strings.HasPrefix(u, "protein_g") {
					idx = i
				}
			}
			if (idx >= 0) != tt.wantSet {
				t.Fatalf("updates = %v, wantSet = %v", updates, tt.wantSet)
			}
			if !tt.wantSet {
				return
			}
			if tt.wantNull {
				if values[idx] != nil {
					t.Errorf("bound value = %v, want NULL", values[idx])
				}
				return
			}
			if got, ok := values[idx].(int); !ok || got != tt.wantValue {
				t.Errorf("bound value = %v, want %d", values[idx], tt.wantValue)
			}
		})
	}
}

// TestBuildEntryUpdatesPlaceholdersAreSequential guards the contract UpdateEntry
// relies on to append the WHERE-clause binds: fragment i uses $(i+1), and there
// are exactly as many values as fragments. Getting this wrong misbinds every
// column, which no amount of field-level testing would reveal.
func TestBuildEntryUpdatesPlaceholdersAreSequential(t *testing.T) {
	body := decodeBody(t, `{"name":"Porridge","amount":"250","protein_g":"30","carbs_g":null,"fat_g":"10","fiber_g":"5","sugar_g":"2"}`)
	updates, values, msg := buildEntryUpdates(body, false)
	if msg != "" {
		t.Fatalf("unexpected rejection: %s", msg)
	}
	if len(updates) != len(values) {
		t.Fatalf("%d fragments but %d values", len(updates), len(values))
	}
	if len(updates) != 7 {
		t.Fatalf("updates = %v, want 7 fragments (name, amount, 5 macros)", updates)
	}
	for i, u := range updates {
		want := fmt.Sprintf("$%d", i+1)
		if !strings.HasSuffix(u, "= "+want) {
			t.Errorf("fragment %d = %q, want it to bind %s", i, u, want)
		}
	}
}

// TestBuildEntryUpdatesEmptyBody documents that a body with nothing recognised
// produces no fragments, which UpdateEntry turns into "No updates provided"
// rather than an UPDATE with an empty SET clause (a SQL syntax error, i.e. a
// 500 for the caller).
func TestBuildEntryUpdatesEmptyBody(t *testing.T) {
	for _, raw := range []string{`{}`, `{"unknown":"x"}`, `{"amount":"250"}`} {
		updates, _, msg := buildEntryUpdates(decodeBody(t, raw), true) // autoCalc drops amount
		if msg != "" {
			t.Fatalf("%s: unexpected rejection: %s", raw, msg)
		}
		if len(updates) != 0 {
			t.Errorf("%s: updates = %v, want none", raw, updates)
		}
	}
}

// TestClassifyAmount pins how CreateEntry reads the raw `amount` field —
// the caller-side half of issue #304.
func TestClassifyAmount(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want amountDecision
		why  string
	}{
		{
			// #303 replaced the fmt.Sprintf("%v", …) coercion with
			// optionalString, so an absent or null key now reaches this
			// function as "" rather than the four-character "<nil>".
			name: "absent, null, or cleared field",
			raw:  "",
			want: amountDecision{Value: 0, HasCalorieEntry: false, Reject: false},
			why:  "a weight-only or macro-only entry must not 400",
		},
		{
			// The sentinel is gone, so this is no longer a stand-in for null:
			// it is a user who typed six literal characters, and it is
			// unparseable. Telling the two apart is the point of #303.
			name: "literal <nil> typed by a user",
			raw:  "<nil>",
			want: amountDecision{Value: 0, HasCalorieEntry: false, Reject: true},
			why:  "present but unparseable; absence is \"\" now, not this",
		},
		{
			name: "empty string",
			raw:  "",
			want: amountDecision{Value: 0, HasCalorieEntry: false, Reject: false},
			why:  "cleared input box, same as absent",
		},
		{
			name: "plain number",
			raw:  "1500",
			want: amountDecision{Value: 1500, HasCalorieEntry: true, Reject: false},
			why:  "the ordinary case",
		},
		{
			name: "expression",
			raw:  "100 + 50 x 2",
			want: amountDecision{Value: 200, HasCalorieEntry: true, Reject: false},
			why:  "the calculator is the point of ParseAmount",
		},
		{
			name: "over the cap",
			raw:  "10000",
			want: amountDecision{Value: 0, HasCalorieEntry: false, Reject: true},
			why:  "above MaxEntryCalories, rejected rather than clamped",
		},
		{
			name: "garbage",
			raw:  "abc",
			want: amountDecision{Value: 0, HasCalorieEntry: false, Reject: true},
			why:  "present but unparseable",
		},
		{
			// fmt.Sprintf("%v", float64) renders anything >= 1e6 like this.
			// The 400 is correct (1e6 is far past MaxEntryCalories) but it
			// comes from the grammar rejecting "e", not from a range check.
			name: "scientific notation from a large JSON number",
			raw:  "1e+06",
			want: amountDecision{Value: 0, HasCalorieEntry: false, Reject: true},
			why:  "rejected on syntax; the range check never runs",
		},
		{
			// The defect from issue #304, now fixed one layer down: this used
			// to be Ok/0, i.e. "no calorie entry", so an entry combining it
			// with a weight was written with amount = 0 and reported success.
			name: "hex-looking input",
			raw:  "0x10",
			want: amountDecision{Value: 0, HasCalorieEntry: false, Reject: true},
			why:  "must 400, not be silently swallowed as zero",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyAmount(tt.raw, MaxEntryCalories)
			if got != tt.want {
				t.Errorf("classifyAmount(%q) = %+v, want %+v (%s)", tt.raw, got, tt.want, tt.why)
			}
		})
	}
}

// TestClassifyAmountZeroIsNotAnError records the judgement call issue #304
// asked for: CreateEntry does NOT 400 when ParseAmount returns Ok with a zero
// value, even for input that was not literally "0".
//
// Every input below is arithmetic the user actually expressed as zero, and
// zero is this handler's "no calorie component" sentinel — the request still
// succeeds if it carries a macro or a weight, and is rejected as "Invalid
// entry data" if it carries nothing else. The input that did not deserve that
// treatment was "0x10", where the zero was a normalization artefact; it is
// rejected in service.ParseAmount now, so it never reaches this function as a
// zero (see the hex case in TestClassifyAmount).
func TestClassifyAmountZeroIsNotAnError(t *testing.T) {
	for _, raw := range []string{"0", "0.0", "-0", "(0)", "0.4", "10-10", "5-5", "0*5", "0/1"} {
		got := classifyAmount(raw, MaxEntryCalories)
		want := amountDecision{Value: 0, HasCalorieEntry: false, Reject: false}
		if got != want {
			t.Errorf("classifyAmount(%q) = %+v, want %+v", raw, got, want)
		}
	}
}
