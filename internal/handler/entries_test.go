package handler

import (
	"testing"

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
			name: "absent field",
			raw:  "<nil>",
			want: amountDecision{Value: 0, HasCalorieEntry: false, Reject: false},
			why:  "fmt.Sprintf(\"%v\", nil); a weight-only entry must not 400",
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
