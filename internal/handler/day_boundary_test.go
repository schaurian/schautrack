package handler

import (
	"net/http/httptest"
	"testing"
	"time"

	"schautrack/internal/model"
)

func strp(s string) *string { return &s }

// TestAIUsageDayIsTheUsersDate: the AI quota row is the user's calendar date,
// so the daily limit resets at their midnight.
func TestAIUsageDayIsTheUsersDate(t *testing.T) {
	cases := []struct {
		tz, clock, want string
	}{
		{"Pacific/Auckland", "2026-11-03T19:00:00Z", "2026-11-04"},
		{"America/Los_Angeles", "2026-11-04T05:00:00Z", "2026-11-03"},
		{"Europe/Berlin", "2026-03-28T23:30:00Z", "2026-03-29"},
		{"Not/A_Zone", "2026-11-03T19:00:00Z", "2026-11-03"}, // invalid stored zone: UTC
	}
	prev := aiClock
	t.Cleanup(func() { aiClock = prev })
	for _, tc := range cases {
		clock, _ := time.Parse(time.RFC3339, tc.clock)
		aiClock = func() time.Time { return clock }
		user := &model.User{Timezone: strp(tc.tz)}
		if got := aiUsageDay(httptest.NewRequest("GET", "/", nil), user); got != tc.want {
			t.Errorf("%s at %s: aiUsageDay = %s, want %s", tc.tz, tc.clock, got, tc.want)
		}
	}
}

// TestExportFilenameUsesTheUsersDate: the server-side export filename is the
// user's calendar date, not the container's UTC date.
func TestExportFilenameUsesTheUsersDate(t *testing.T) {
	clock, _ := time.Parse(time.RFC3339, "2026-11-03T19:00:00Z")
	cases := map[string]string{
		"Pacific/Auckland":    "schautrack-export-2026-11-04.json",
		"America/Los_Angeles": "schautrack-export-2026-11-03.json",
		"UTC":                 "schautrack-export-2026-11-03.json",
	}
	for tz, want := range cases {
		if got := exportFilename(clock, tz); got != want {
			t.Errorf("exportFilename(%s) = %s, want %s", tz, got, want)
		}
	}
}

// TestRegistrationTimezone: an unloadable zone from the registration form is
// replaced (client zone, then UTC) instead of being stored verbatim.
func TestRegistrationTimezone(t *testing.T) {
	cases := []struct {
		requested, client, want string
	}{
		{"Pacific/Auckland", "Europe/Berlin", "Pacific/Auckland"},
		{" Pacific/Auckland ", "", "Pacific/Auckland"},
		{"Etc/Unknown", "Europe/Berlin", "Europe/Berlin"},
		{"Mars/Olympus_Mons", "", "UTC"},
		{"Local", "", "UTC"},
		{"", "America/Los_Angeles", "America/Los_Angeles"},
		{"", "", "UTC"},
	}
	for _, tc := range cases {
		if got := registrationTimezone(tc.requested, tc.client); got != tc.want {
			t.Errorf("registrationTimezone(%q, %q) = %q, want %q", tc.requested, tc.client, got, tc.want)
		}
	}
}

// TestInvalidStoredTimezoneFallsBack: a stored name the server cannot load
// reads as "no timezone", so the request's zone (then UTC) is used and the
// client is never handed a name Intl would throw on.
func TestInvalidStoredTimezoneFallsBack(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Timezone", "Europe/Berlin")
	if got := getUserTimezone(r, &model.User{Timezone: strp("Mars/Olympus_Mons")}); got != "Europe/Berlin" {
		t.Errorf("invalid stored zone: getUserTimezone = %q, want the client's Europe/Berlin", got)
	}
	if got := getUserTimezone(httptest.NewRequest("GET", "/", nil), &model.User{Timezone: strp("Local")}); got != "UTC" {
		t.Errorf(`"Local" stored: getUserTimezone = %q, want UTC`, got)
	}
	if got := getUserTimezone(r, &model.User{Timezone: strp("Pacific/Auckland")}); got != "Pacific/Auckland" {
		t.Errorf("valid stored zone: getUserTimezone = %q, want Pacific/Auckland", got)
	}
}
