package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/session"
)

// A users.timezone value the server cannot load can exist from before
// validation (registration and import stored names verbatim). Every surface
// must read it as the UTC actually in force — never hand the raw name to the
// client, where Intl throws on it and the dashboard used to crash.
const badZone = "Mars/Olympus_Mons"

// sessionRequest builds a GET as the session-authenticated app would send it,
// with the user loaded exactly the way RequireLogin loads them.
func (e *v1Env) sessionRequest(method, path string, body *strings.Reader, userID int) *http.Request {
	e.t.Helper()
	user, err := middleware.GetUserByID(e.Ctx, e.Pool, userID)
	if err != nil || user == nil {
		e.t.Fatalf("loading user %d: %v", userID, err)
	}
	if body == nil {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, path, body)
	ctx := middleware.WithTestUser(e.Ctx, user)
	ctx = session.WithTestSession(ctx, &session.Session{ID: "tz-test", Data: map[string]any{}, MaxAge: session.AnonMaxAge})
	return r.WithContext(ctx)
}

func (e *v1Env) setTimezone(userID int, tz string) {
	e.t.Helper()
	if _, err := e.Pool.Exec(e.Ctx, `UPDATE users SET timezone = $1, timezone_manual = FALSE WHERE id = $2`, tz, userID); err != nil {
		e.t.Fatal(err)
	}
}

func (e *v1Env) storedTimezone(userID int) (string, bool) {
	e.t.Helper()
	var tz *string
	var manual *bool
	if err := e.Pool.QueryRow(e.Ctx, `SELECT timezone, timezone_manual FROM users WHERE id = $1`, userID).Scan(&tz, &manual); err != nil {
		e.t.Fatal(err)
	}
	s := "<NULL>"
	if tz != nil {
		s = *tz
	}
	return s, manual != nil && *manual
}

func TestInvalidStoredTimezoneReadsAsUTCOnSessionEndpoints(t *testing.T) {
	e := newV1Env(t)
	e.setTimezone(e.UserID, badZone)

	cfg := &config.Config{}
	cache := database.NewSettingsCache(e.Pool)
	entries := &EntriesHandler{Pool: e.Pool, Cfg: cfg, Settings: cache}

	cases := []struct {
		name    string
		path    string
		handler http.HandlerFunc
		// paths into the JSON body that carry a timezone
		fields [][]string
	}{
		{"me", "/api/me", Me(e.Pool, "", cache, cfg), [][]string{{"user", "timezone"}}},
		{"settings", "/api/settings", Settings(e.Pool, "", cache, cfg), [][]string{{"user", "timezone"}}},
		{"dashboard", "/api/dashboard", entries.Dashboard, [][]string{{"timeZone"}, {"user", "timezone"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler(rec, e.sessionRequest(http.MethodGet, tc.path, nil, e.UserID))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s = %d: %s", tc.path, rec.Code, rec.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			for _, f := range tc.fields {
				var v any = body
				for _, k := range f {
					m, _ := v.(map[string]any)
					v = m[k]
				}
				if v != "UTC" {
					t.Errorf("%s %v = %v, want UTC", tc.path, f, v)
				}
			}
		})
	}
}

func TestLinkedUserInvalidTimezoneReadsAsUTC(t *testing.T) {
	e := newV1Env(t)
	friendID, _ := e.seedUser("-friend")
	e.setTimezone(friendID, badZone)
	e.link(friendID, e.UserID, allShares(), allShares())

	t.Run("session dashboard links", func(t *testing.T) {
		links, err := service.GetAcceptedLinkUsers(e.Ctx, e.Pool, e.UserID)
		if err != nil {
			t.Fatal(err)
		}
		if len(links) != 1 {
			t.Fatalf("got %d links, want 1", len(links))
		}
		if links[0].Timezone != "UTC" {
			t.Errorf("linked user timezone = %q, want UTC", links[0].Timezone)
		}
	})

	t.Run("GET /api/v1/links", func(t *testing.T) {
		rec := e.get("/api/v1/links", e.token(service.ScopeLinksRead))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var page v1List[v1Link]
		decodeJSON(t, rec, &page)
		if len(page.Data) != 1 || page.Data[0].Timezone != "UTC" {
			t.Errorf("links = %+v, want one link with timezone UTC", page.Data)
		}
	})
}

// "Local" passes time.LoadLocation but names the server's zone, not one the
// user chose; it must not be stored by either write path. Neither may "" on v1.
func TestTimezoneLocalIsRejected(t *testing.T) {
	e := newV1Env(t)

	t.Run("settings preferences", func(t *testing.T) {
		e.setTimezone(e.UserID, "Europe/Berlin")
		h := &SettingsHandler{Pool: e.Pool}
		rec := httptest.NewRecorder()
		req := e.sessionRequest(http.MethodPost, "/settings/preferences",
			strings.NewReader(`{"weight_unit":"kg","timezone":"Local","language":""}`), e.UserID)
		req.Header.Set("Content-Type", "application/json")
		h.Preferences(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		if tz, manual := e.storedTimezone(e.UserID); tz != "Europe/Berlin" || manual {
			t.Errorf("stored timezone = %q (manual %v), want Europe/Berlin unchanged", tz, manual)
		}
	})

	// "" also loads (as UTC) but is not a zone either: storing it pinned the
	// account to UTC days with timezone_manual set.
	for _, bad := range []string{"Local", ""} {
		t.Run(fmt.Sprintf("PATCH /api/v1/me timezone=%q", bad), func(t *testing.T) {
			e.setTimezone(e.UserID, "Europe/Berlin")
			body, _ := json.Marshal(map[string]string{"timezone": bad})
			rec := e.patch("/api/v1/me", e.token(service.ScopeSettingsWrite), string(body))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422: %s", rec.Code, rec.Body.String())
			}
			if tz, manual := e.storedTimezone(e.UserID); tz != "Europe/Berlin" || manual {
				t.Errorf("stored timezone = %q (manual %v), want Europe/Berlin unchanged", tz, manual)
			}
		})
	}
}

// An import file with "timezone": "" carries no zone. It used to store an empty string and
// pin timezone_manual, after which every day boundary was UTC.
func TestImportEmptyTimezoneIsAbsent(t *testing.T) {
	e := newV1Env(t)
	e.setTimezone(e.UserID, "Pacific/Auckland")

	h := &EntriesHandler{Pool: e.Pool}
	req := buildImportRequest(t, "import_file",
		`{"user":{"timezone":"","weight_unit":"kg"},"entries":[{"date":"2026-11-01","amount":100}]}`)
	user, err := middleware.GetUserByID(e.Ctx, e.Pool, e.UserID)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(session.WithTestSession(middleware.WithTestUser(e.Ctx, user),
		&session.Session{ID: "tz-test", Data: map[string]any{}, MaxAge: session.AnonMaxAge}))
	rec := httptest.NewRecorder()
	h.Import(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status = %d: %s", rec.Code, rec.Body.String())
	}
	if tz, manual := e.storedTimezone(e.UserID); tz != "Pacific/Auckland" || manual {
		t.Errorf("after import: timezone = %q, manual = %v; want Pacific/Auckland, not pinned", tz, manual)
	}

	// A file whose only "setting" is the empty zone has nothing to import.
	only := buildImportRequest(t, "import_file", `{"user":{"timezone":""}}`)
	only = only.WithContext(req.Context())
	rec = httptest.NewRecorder()
	h.Import(rec, only)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("import of {timezone:\"\"} only = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}
