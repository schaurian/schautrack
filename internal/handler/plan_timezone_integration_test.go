package handler

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"schautrack/internal/service"
)

// TestPlanDatesUseUsersCalendarDay pins the plan's clock to instants that fall
// on different calendar days in UTC and in the user's zone, and checks that
// every date-valued answer the plan gives — the ETA and the body-fat reading's
// age — is computed from the user's today, the same day the dashboard calls
// "Today" and the day the reading was logged under.
//
// Before the fix the handler passed the server's time.Now() (UTC in the
// container) to AssemblePlan, so an Auckland user at 08:00 got an ETA a day
// early and a reading logged "today" reported as -1 days old, and a Los
// Angeles user at 21:00 got an ETA a day late.
func TestPlanDatesUseUsersCalendarDay(t *testing.T) {
	cases := []struct {
		name      string
		tz        string
		clock     string // RFC3339, UTC
		localDate string // the user's calendar date at clock
		wantETA   string // localDate + 14 days (1 kg at 0.5 kg/week)
	}{
		{"auckland morning, UTC still yesterday", "Pacific/Auckland", "2026-11-03T19:00:00Z", "2026-11-04", "2026-11-18"},
		{"los angeles evening, UTC already tomorrow", "America/Los_Angeles", "2026-11-04T05:00:00Z", "2026-11-03", "2026-11-17"},
		{"berlin just after spring-forward midnight", "Europe/Berlin", "2026-03-28T23:30:00Z", "2026-03-29", "2026-04-12"},
		{"berlin on the 25-hour fall-back day", "Europe/Berlin", "2026-10-25T23:30:00Z", "2026-10-26", "2026-11-09"},
		{"year boundary in auckland", "Pacific/Auckland", "2026-12-31T12:00:00Z", "2027-01-01", "2027-01-15"},
		// The 14-day window below crosses a DST transition, and the start's wall
		// clock sits within an hour of midnight, so "14 days" and "336 hours"
		// land on different calendar days. These catch an ETA computed with
		// Add(n*24h) instead of calendar AddDate.
		{"berlin 23:30 the evening before spring-forward", "Europe/Berlin", "2026-03-28T22:30:00Z", "2026-03-28", "2026-04-11"},
		{"berlin 00:30 two weeks before fall-back", "Europe/Berlin", "2026-10-23T22:30:00Z", "2026-10-24", "2026-11-07"},
		{"los angeles 23:30 a week before spring-forward", "America/Los_Angeles", "2026-03-02T07:30:00Z", "2026-03-01", "2026-03-15"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newV1Env(t)

			clock, err := time.Parse(time.RFC3339, tc.clock)
			if err != nil {
				t.Fatal(err)
			}
			if got := service.FormatDateInTz(clock, tc.tz); got != tc.localDate {
				t.Fatalf("case is mis-specified: %s in %s is %s, not %s", tc.clock, tc.tz, got, tc.localDate)
			}
			// Every case must sit on a boundary: either UTC and the user disagree
			// on the date, or the ETA window spans a DST change.
			loc, err := time.LoadLocation(tc.tz)
			if err != nil {
				t.Fatal(err)
			}
			_, offStart := clock.In(loc).Zone()
			_, offEnd := clock.In(loc).AddDate(0, 0, 14).Zone()
			if clock.UTC().Format("2006-01-02") == tc.localDate && offStart == offEnd {
				t.Fatalf("case is not a boundary case: UTC date equals local date %s and no DST change in the window", tc.localDate)
			}
			prev := planClock
			planClock = func() time.Time { return clock }
			t.Cleanup(func() { planClock = prev })

			if _, err := e.Pool.Exec(e.Ctx, `
				UPDATE users SET timezone = $1, weight_unit = 'kg', height_cm = 180,
				       birth_year = 1990, sex = 'male', activity_level = 'moderate'
				 WHERE id = $2`, tc.tz, e.UserID); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Pool.Exec(e.Ctx, `
				INSERT INTO weight_entries (user_id, entry_date, weight, body_fat)
				VALUES ($1, $2, 80, 25)`, e.UserID, tc.localDate); err != nil {
				t.Fatal(err)
			}
			if _, err := e.Pool.Exec(e.Ctx, `
				INSERT INTO weight_goals (user_id, start_weight, start_date, target_weight, pace_mode, rate_kg_per_week)
				VALUES ($1, 80, $2, 79, 'rate', 0.5)`, e.UserID, tc.localDate); err != nil {
				t.Fatal(err)
			}

			rec := e.get("/api/v1/plan", e.token(service.ScopePlanRead))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET /api/v1/plan = %d: %s", rec.Code, rec.Body.String())
			}
			var resp struct {
				Computed *struct {
					ETADate *string `json:"etaDate"`
				} `json:"computed"`
				Composition *struct {
					Date    string `json:"date"`
					AgeDays int    `json:"ageDays"`
				} `json:"composition"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Computed == nil || resp.Computed.ETADate == nil {
				t.Fatalf("no computed ETA in response: %s", rec.Body.String())
			}
			if got := *resp.Computed.ETADate; got != tc.wantETA {
				t.Errorf("etaDate = %s, want %s (user's today %s + 14 days)", got, tc.wantETA, tc.localDate)
			}
			if resp.Composition == nil {
				t.Fatalf("no composition in response: %s", rec.Body.String())
			}
			if resp.Composition.AgeDays != 0 {
				t.Errorf("body-fat reading logged today (%s) is %d days old, want 0", resp.Composition.Date, resp.Composition.AgeDays)
			}
		})
	}
}
