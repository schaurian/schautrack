package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"schautrack/internal/model"
	"schautrack/internal/session"
)

// probe returns a handler that records whether it ran.
func probe() (http.Handler, *bool) {
	ran := false
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	}), &ran
}

func decodeErrorBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON (%q): %v", rec.Body.String(), err)
	}
	return body
}

// --- IsAdmin --------------------------------------------------------------

// TestIsAdmin is the table behind the admin panel, which can rewrite live
// configuration. Every row here is a way an admin check can go wrong; the
// empty-ADMIN_EMAIL rows are the ones that would turn every logged-in user
// into an administrator on a deployment that simply forgot the variable.
func TestIsAdmin(t *testing.T) {
	user := func(email string) *model.User { return &model.User{ID: 1, Email: email} }

	tests := []struct {
		name       string
		user       *model.User
		adminEmail string
		want       bool
		why        string
	}{
		{"exact match", user("admin@example.com"), "admin@example.com", true, ""},
		{"different user", user("someone@example.com"), "admin@example.com", false, ""},

		// The match is case-insensitive: addresses are stored lowercased, but
		// ADMIN_EMAIL is typed by a human into an env file.
		{"admin email upper-cased", user("admin@example.com"), "ADMIN@EXAMPLE.COM", true, ""},
		{"stored email upper-cased", user("Admin@Example.COM"), "admin@example.com", true, ""},

		// ADMIN_EMAIL is read raw from the environment; a trailing newline out
		// of a .env file or a Kubernetes secret must not lock the admin out.
		{"admin email with trailing newline", user("admin@example.com"), "admin@example.com\n", true, ""},
		{"admin email padded with spaces", user("admin@example.com"), "  admin@example.com  ", true, ""},

		// …but the stored address is never trimmed, so a padded account cannot
		// impersonate the admin.
		{"padded stored email does not match", user("admin@example.com "), "admin@example.com", false,
			"an account whose stored address has trailing whitespace must not match ADMIN_EMAIL"},

		// The rows that matter most.
		{"ADMIN_EMAIL unset", user("anyone@example.com"), "", false,
			"an unset ADMIN_EMAIL must make NOBODY an admin"},
		{"ADMIN_EMAIL unset, user email also empty", user(""), "", false,
			"two empty strings must not compare equal into admin rights"},
		{"ADMIN_EMAIL whitespace only", user("anyone@example.com"), "   ", false,
			"a whitespace-only ADMIN_EMAIL is an unset one"},
		{"ADMIN_EMAIL whitespace only, user email whitespace", user(" "), " ", false,
			"whitespace must never authenticate an admin"},
		{"empty stored email against a real ADMIN_EMAIL", user(""), "admin@example.com", false, ""},

		{"nil user", nil, "admin@example.com", false, "an unauthenticated request has no admin rights"},
		{"nil user and unset ADMIN_EMAIL", nil, "", false, ""},

		// Not a substring/prefix match.
		{"prefix of the admin address", user("admin@example.co"), "admin@example.com", false, ""},
		{"admin address as a substring", user("notadmin@example.com"), "admin@example.com", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAdmin(tt.user, tt.adminEmail); got != tt.want {
				msg := tt.why
				if msg == "" {
					msg = "wrong admin decision"
				}
				t.Errorf("IsAdmin(%v, %q) = %v, want %v — %s", tt.user, tt.adminEmail, got, tt.want, msg)
			}
		})
	}
}

// --- RequireAdmin ---------------------------------------------------------

func TestRequireAdmin(t *testing.T) {
	admin := &model.User{ID: 1, Email: "admin@example.com"}
	other := &model.User{ID: 2, Email: "user@example.com"}

	tests := []struct {
		name       string
		user       *model.User // nil ⇒ unauthenticated request
		adminEmail string
		wantStatus int
		wantRun    bool
	}{
		{"no session at all", nil, "admin@example.com", http.StatusForbidden, false},
		{"logged in but not the admin", other, "admin@example.com", http.StatusForbidden, false},
		{"the admin", admin, "admin@example.com", http.StatusOK, true},
		{"the admin, ADMIN_EMAIL cased differently", admin, "Admin@Example.com", http.StatusOK, true},
		{"ADMIN_EMAIL unset, ordinary user", other, "", http.StatusForbidden, false},
		{"ADMIN_EMAIL unset, the would-be admin", admin, "", http.StatusForbidden, false},
		{"ADMIN_EMAIL unset, no session", nil, "", http.StatusForbidden, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next, ran := probe()
			req := httptest.NewRequest(http.MethodGet, "/api/admin", nil)
			if tt.user != nil {
				req = req.WithContext(WithTestUser(req.Context(), tt.user))
			}
			rec := httptest.NewRecorder()

			RequireAdmin(tt.adminEmail)(next).ServeHTTP(rec, req)

			if *ran != tt.wantRun {
				t.Errorf("handler ran = %v, want %v — the admin panel was reachable by the wrong caller", *ran, tt.wantRun)
			}
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusForbidden {
				if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
				if body := decodeErrorBody(t, rec); body["error"] != "Forbidden" {
					t.Errorf("error = %v, want %q", body["error"], "Forbidden")
				}
			}
		})
	}
}

// TestRequireAdminDoesNotLeakWhetherAdminExists checks the 403 body is the same
// whether ADMIN_EMAIL is unset, belongs to somebody else, or the caller simply
// is not it. A differing message would tell an attacker whether the deployment
// has an admin account worth attacking.
func TestRequireAdminDoesNotLeakWhetherAdminExists(t *testing.T) {
	user := &model.User{ID: 2, Email: "user@example.com"}
	var bodies []string
	for _, adminEmail := range []string{"", "admin@example.com", "nobody@example.com"} {
		next, _ := probe()
		req := httptest.NewRequest(http.MethodGet, "/api/admin", nil).
			WithContext(WithTestUser(t.Context(), user))
		rec := httptest.NewRecorder()
		RequireAdmin(adminEmail)(next).ServeHTTP(rec, req)
		bodies = append(bodies, rec.Body.String())
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("403 bodies differ by ADMIN_EMAIL configuration:\n%q\n%q", bodies[0], bodies[i])
		}
	}
}

// --- RequireLogin ---------------------------------------------------------

func TestRequireLoginRejectsAnonymous(t *testing.T) {
	next, ran := probe()
	rec := httptest.NewRecorder()

	RequireLogin(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/settings", nil))

	if *ran {
		t.Fatal("handler ran for an unauthenticated request")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if body := decodeErrorBody(t, rec); body["error"] != "Authentication required" {
		t.Errorf("error = %v, want %q", body["error"], "Authentication required")
	}
}

func TestRequireLoginAllowsAuthenticated(t *testing.T) {
	next, ran := probe()
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil).
		WithContext(WithTestUser(t.Context(), &model.User{ID: 7, Email: "user@example.com"}))
	rec := httptest.NewRecorder()

	RequireLogin(next).ServeHTTP(rec, req)

	if !*ran {
		t.Error("handler did not run for an authenticated request")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestRequireLoginIgnoresASessionWithoutAUser guards the boundary between
// AttachUser and RequireLogin: a session cookie exists for anonymous visitors
// too (CSRF tokens live in it), so the presence of a session must never be
// mistaken for authentication.
func TestRequireLoginIgnoresASessionWithoutAUser(t *testing.T) {
	next, ran := probe()
	sess := &session.Session{Data: map[string]any{"csrf": "abc"}}
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil).
		WithContext(session.WithTestSession(t.Context(), sess))
	rec := httptest.NewRecorder()

	RequireLogin(next).ServeHTTP(rec, req)

	if *ran {
		t.Fatal("an anonymous session was treated as a logged-in user")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// --- RequireLocalAuth -----------------------------------------------------

// TestRequireLocalAuth covers the gate on password / 2FA / passkey / email
// routes. A federated account has no local password to change, and the IdP —
// not this app — owns its authentication; letting an OIDC session set a local
// password would create a second, weaker way into the account.
func TestRequireLocalAuth(t *testing.T) {
	tests := []struct {
		name       string
		sess       *session.Session
		wantRun    bool
		wantStatus int
	}{
		{"password session", &session.Session{Data: map[string]any{"auth_method": "password"}}, true, http.StatusOK},
		{"passkey session", &session.Session{Data: map[string]any{"auth_method": "passkey"}}, true, http.StatusOK},
		{"oidc session", &session.Session{Data: map[string]any{"auth_method": "oidc"}}, false, http.StatusForbidden},
		{"session with no auth_method", &session.Session{Data: map[string]any{}}, true, http.StatusOK},

		// No session is refused outright (#373). This used to pass through on
		// the grounds that RequireLogin is always mounted above it — true of
		// all nine current registrations, and enforced by nothing. An
		// unwritten ordering convention guarding the password change, the
		// email-change flow and every 2FA route is one refactor away from
		// being no guard at all, so the middleware now fails closed on its
		// own.
		{"no session at all", nil, false, http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next, ran := probe()
			req := httptest.NewRequest(http.MethodPost, "/settings/password", nil)
			if tt.sess != nil {
				req = req.WithContext(session.WithTestSession(req.Context(), tt.sess))
			}
			rec := httptest.NewRecorder()

			RequireLocalAuth(next).ServeHTTP(rec, req)

			if *ran != tt.wantRun {
				t.Errorf("handler ran = %v, want %v", *ran, tt.wantRun)
			}
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantStatus == http.StatusForbidden {
				if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
				body := decodeErrorBody(t, rec)
				if msg, _ := body["error"].(string); msg == "" {
					t.Error("the 403 must explain why: a federated user needs to be told to manage auth at their IdP")
				}
			}
		})
	}
}

// TestRequireLocalAuthBlocksEveryLocalAuthRoute expresses the route list as a
// table. These are the paths that mount RequireLocalAuth in cmd/server/main.go;
// an OIDC session must be refused on all of them, not just the password one.
func TestRequireLocalAuthBlocksEveryLocalAuthRoute(t *testing.T) {
	routes := []string{
		"/settings/password",
		"/settings/email/request",
		"/settings/email/verify",
		"/settings/email/cancel",
		"/2fa/setup",
		"/2fa/cancel",
		"/2fa/enable",
		"/2fa/disable",
		"/2fa/backup-codes",
	}
	for _, path := range routes {
		t.Run(path, func(t *testing.T) {
			next, ran := probe()
			sess := &session.Session{Data: map[string]any{"auth_method": "oidc"}}
			req := httptest.NewRequest(http.MethodPost, path, nil).
				WithContext(session.WithTestSession(t.Context(), sess))
			rec := httptest.NewRecorder()

			RequireLocalAuth(next).ServeHTTP(rec, req)

			if *ran {
				t.Errorf("an OIDC session reached %s", path)
			}
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
		})
	}
}

// TestAuthMiddlewareMountOrder guards the assumption the two authorization
// middlewares are written against.
//
// RequireLocalAuth only inspects the session's auth_method; with no session at
// all it passes the request through. That is safe exactly because it is never
// mounted without RequireLogin above it, which has already rejected an
// anonymous caller. RequireAdmin does fail closed on its own, but the same
// ordering is what makes its 403 mean "you are not the admin" rather than "you
// are not logged in".
//
// Neither property is enforced by the type system, so it is enforced here,
// against the real route table. (RequireScope on /api/v1 solves the same
// problem in code by returning 401 when no token is present — see apiauth.go.)
func TestAuthMiddlewareMountOrder(t *testing.T) {
	const mainGo = "../../cmd/server/main.go"

	routes := parseRoutes(t, mainGo)
	if len(routes) < 40 {
		t.Fatalf("only %d routes parsed out of %s; the mount-order guard is not looking at the real "+
			"route table", len(routes), mainGo)
	}

	var sawLocalAuth, sawAdmin int
	for _, rt := range routes {
		for _, gate := range []string{"RequireLocalAuth", "RequireAdmin"} {
			if !strings.Contains(rt.chain, gate) {
				continue
			}
			if gate == "RequireLocalAuth" {
				sawLocalAuth++
			} else {
				sawAdmin++
			}
			if !strings.Contains(rt.chain, "RequireLogin") {
				t.Errorf("%s:%d — %s %s mounts %s without RequireLogin above it. %s does not "+
					"authenticate; an anonymous request would pass straight through it.",
					mainGo, rt.line, rt.method, rt.path, gate, gate)
			}
		}
	}
	if sawLocalAuth == 0 {
		t.Error("no RequireLocalAuth routes found; either they were removed or the guard stopped matching")
	}
	if sawAdmin == 0 {
		t.Error("no RequireAdmin routes found; either they were removed or the guard stopped matching")
	}
}

// --- GetCurrentUser -------------------------------------------------------

func TestGetCurrentUserReturnsNilWhenAbsent(t *testing.T) {
	if u := GetCurrentUser(httptest.NewRequest(http.MethodGet, "/", nil)); u != nil {
		t.Errorf("GetCurrentUser = %v, want nil on an unauthenticated request", u)
	}
}

func TestGetCurrentUserRoundTrips(t *testing.T) {
	want := &model.User{ID: 42, Email: "user@example.com"}
	req := httptest.NewRequest(http.MethodGet, "/", nil).
		WithContext(WithTestUser(t.Context(), want))
	got := GetCurrentUser(req)
	if got == nil || got.ID != want.ID || got.Email != want.Email {
		t.Errorf("GetCurrentUser = %v, want %v", got, want)
	}
}
