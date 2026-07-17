package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/oauth2"

	"schautrack/internal/config"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/session"
)

func TestSafeNextPath(t *testing.T) {
	const fb = "/settings"
	tests := []struct {
		name string
		next string
		want string
	}{
		{"empty falls back", "", fb},
		{"simple path", "/dashboard", "/dashboard"},
		{"nested path", "/settings/security", "/settings/security"},
		{"path with query kept", "/foods?tab=recent", "/foods?tab=recent"},
		{"root path", "/", "/"},

		// Open-redirect vectors that must all fall back.
		{"protocol relative", "//evil.com", fb},
		{"backslash obfuscation", "/\\evil.com", fb},
		{"backslash double", "/\\/evil.com", fb},
		{"absolute http url", "http://evil.com", fb},
		{"absolute https url", "https://evil.com/path", fb},
		{"scheme relative with backslashes", "\\\\evil.com", fb},
		{"javascript scheme", "javascript:alert(1)", fb},
		{"no leading slash", "evil.com", fb},
		{"leading space then slash", " /dashboard", fb},
		{"embedded newline", "/foo\nbar", fb},
		{"embedded CR", "/foo\rbar", fb},
		{"null byte", "/foo\x00bar", fb},
		{"tab char", "/foo\tbar", fb},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeNextPath(tt.next, fb); got != tt.want {
				t.Errorf("safeNextPath(%q) = %q, want %q", tt.next, got, tt.want)
			}
		})
	}
}

// --- Test helpers -----------------------------------------------------------

const testAuthURL = "https://idp.example.test/authorize"

func newTestSession() *session.Session {
	return &session.Session{
		ID:     "test-session-id",
		Data:   make(map[string]any),
		MaxAge: session.AnonMaxAge,
	}
}

// testOAuthConfig builds an *oauth2.Config whose AuthCodeURL can be assembled
// without any network access, so Login/StepUpInit redirect construction is
// exercisable in a unit test.
func testOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:    "test-client",
		Endpoint:    oauth2.Endpoint{AuthURL: testAuthURL},
		RedirectURL: "https://app.example.test/auth/oidc/callback",
		Scopes:      []string{"openid", "email", "profile"},
	}
}

// reqWith builds a request carrying sess in context, and optionally an
// authenticated user (pass nil to stay anonymous).
func reqWith(method, target string, sess *session.Session, user *model.User) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	ctx := session.WithTestSession(r.Context(), sess)
	if user != nil {
		ctx = middleware.WithTestUser(ctx, user)
	}
	return r.WithContext(ctx)
}

func testUser() *model.User { return &model.User{ID: 1, Email: "user@example.test"} }

// --- Callback: state validation (the check before any IdP/DB interaction) ---

func TestOIDCCallback_InvalidState(t *testing.T) {
	tests := []struct {
		name          string
		savedState    string // "" means no oidc_state was stored in the session
		providedState string // value of the ?state= query param
	}{
		{"no saved state", "", "attacker-supplied"},
		{"state mismatch", "abc123", "xyz789"},
		{"empty provided state", "abc123", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &OIDCHandler{} // nil deps are fine: this path returns before using them

			sess := newTestSession()
			if tt.savedState != "" {
				sess.Set("oidc_state", tt.savedState)
			}
			// Always seed nonce+intent so we can assert they get cleaned up.
			sess.Set("oidc_nonce", "saved-nonce")
			sess.Set("oidc_intent", "login")

			target := "/auth/oidc/callback"
			if tt.providedState != "" {
				target += "?state=" + url.QueryEscape(tt.providedState)
			}
			r := reqWith(http.MethodGet, target, sess, nil)
			w := httptest.NewRecorder()

			h.Callback(w, r)

			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
			}
			if loc := w.Header().Get("Location"); loc != "/login?error=invalid_state" {
				t.Errorf("Location = %q, want /login?error=invalid_state", loc)
			}
			// The handler must scrub the one-time OIDC values from the session
			// even on the reject path, so a stale state can't be replayed.
			for _, k := range []string{"oidc_state", "oidc_nonce", "oidc_intent"} {
				if v := sess.Get(k); v != nil {
					t.Errorf("session key %q not cleaned up: got %v", k, v)
				}
			}
		})
	}
}

// --- Login: state/nonce round-trip + login-vs-link intent branching ---------

func TestOIDCLogin_AnonymousStartsLoginFlow(t *testing.T) {
	h := &OIDCHandler{oauth2Config: testOAuthConfig()}
	sess := newTestSession()
	r := reqWith(http.MethodGet, "/auth/oidc/login", sess, nil) // no user
	w := httptest.NewRecorder()

	h.Login(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	if got := sess.GetString("oidc_intent"); got != "login" {
		t.Errorf("oidc_intent = %q, want login", got)
	}

	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Host != "idp.example.test" || loc.Path != "/authorize" {
		t.Errorf("redirect target = %q, want the IdP authorize endpoint", loc)
	}

	// The state placed in the outgoing redirect MUST equal the state stored in
	// the session — that equality is exactly what Callback later validates.
	stateInURL := loc.Query().Get("state")
	if stateInURL == "" {
		t.Fatal("no state param in redirect URL")
	}
	if savedState := sess.GetString("oidc_state"); savedState != stateInURL {
		t.Errorf("session oidc_state %q != state in redirect %q", savedState, stateInURL)
	}

	// Likewise the nonce is threaded through and stored for Callback to compare
	// against the ID token's nonce claim.
	nonceInURL := loc.Query().Get("nonce")
	if nonceInURL == "" {
		t.Fatal("no nonce param in redirect URL")
	}
	if savedNonce := sess.GetString("oidc_nonce"); savedNonce != nonceInURL {
		t.Errorf("session oidc_nonce %q != nonce in redirect %q", savedNonce, nonceInURL)
	}
}

func TestOIDCLogin_LoggedInStartsLinkFlow(t *testing.T) {
	h := &OIDCHandler{oauth2Config: testOAuthConfig()}
	sess := newTestSession()
	r := reqWith(http.MethodGet, "/auth/oidc/login", sess, testUser()) // already logged in
	w := httptest.NewRecorder()

	h.Login(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	if got := sess.GetString("oidc_intent"); got != "link" {
		t.Errorf("oidc_intent = %q, want link (logged-in user triggers link flow)", got)
	}
}

// --- StepUpInit: auth guard + next-param safety -----------------------------

func TestOIDCStepUpInit_AnonymousRedirectsToLogin(t *testing.T) {
	h := &OIDCHandler{oauth2Config: testOAuthConfig()}
	sess := newTestSession()
	r := reqWith(http.MethodGet, "/auth/oidc/step-up?next=/settings", sess, nil) // no user
	w := httptest.NewRecorder()

	h.StepUpInit(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
	// The guard returns before touching the session's OIDC fields.
	if v := sess.Get("oidc_intent"); v != nil {
		t.Errorf("oidc_intent should not be set for an anonymous step-up, got %v", v)
	}
}

func TestOIDCStepUpInit_LoggedInStoresSafeNext(t *testing.T) {
	tests := []struct {
		name     string
		next     string
		wantNext string
	}{
		{"safe relative path kept", "/settings/security", "/settings/security"},
		{"open-redirect vector rejected", "//evil.com", "/settings"},
		{"empty next falls back", "", "/settings"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &OIDCHandler{oauth2Config: testOAuthConfig()}
			sess := newTestSession()
			target := "/auth/oidc/step-up"
			if tt.next != "" {
				target += "?next=" + url.QueryEscape(tt.next)
			}
			r := reqWith(http.MethodGet, target, sess, testUser())
			w := httptest.NewRecorder()

			h.StepUpInit(w, r)

			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
			}
			if got := sess.GetString("oidc_intent"); got != "step_up" {
				t.Errorf("oidc_intent = %q, want step_up", got)
			}
			if got := sess.GetString("oidc_step_up_next"); got != tt.wantNext {
				t.Errorf("oidc_step_up_next = %q, want %q", got, tt.wantNext)
			}
			// Redirect goes to the IdP, not straight back to the app.
			loc, err := url.Parse(w.Header().Get("Location"))
			if err != nil || loc.Host != "idp.example.test" || loc.Path != "/authorize" {
				t.Errorf("redirect target = %q, want the IdP authorize endpoint", w.Header().Get("Location"))
			}
		})
	}
}

// --- handleLink: guards that fire before any database write -----------------

func TestOIDCHandleLink_NoUserRedirectsToLogin(t *testing.T) {
	h := &OIDCHandler{} // nil Pool: this path returns before the DB lookup
	sess := newTestSession()
	r := reqWith(http.MethodGet, "/auth/oidc/callback", sess, nil) // not logged in
	w := httptest.NewRecorder()

	h.handleLink(w, r, sess, "google", "sub-123", "user@example.test", true)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

func TestOIDCHandleLink_RejectsUnverifiedEmail(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		emailVerified bool
	}{
		{"missing email", "", true},
		{"unverified email", "user@example.test", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &OIDCHandler{} // nil Pool: rejection happens before the DB lookup
			sess := newTestSession()
			r := reqWith(http.MethodGet, "/auth/oidc/callback", sess, testUser())
			w := httptest.NewRecorder()

			h.handleLink(w, r, sess, "google", "sub-123", tt.email, tt.emailVerified)

			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
			}
			if loc := w.Header().Get("Location"); loc != "/settings?error=oidc_email_unverified" {
				t.Errorf("Location = %q, want /settings?error=oidc_email_unverified", loc)
			}
		})
	}
}

// --- handleStepUp: auth guard before the subject-match DB lookup ------------

func TestOIDCHandleStepUp_NoUserRedirectsToLogin(t *testing.T) {
	h := &OIDCHandler{} // nil Pool: returns before FindOIDCAccount
	sess := newTestSession()
	r := reqWith(http.MethodGet, "/auth/oidc/callback", sess, nil) // not logged in
	w := httptest.NewRecorder()

	h.handleStepUp(w, r, sess, "google", "sub-123")

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

// --- canAutoCreate: fail-closed when invites are required -------------------

func TestOIDCCanAutoCreate_FailsClosedOnRequireInvite(t *testing.T) {
	// OIDCRequireInvite short-circuits to false before the settings cache is
	// consulted, so a nil Settings is safe here.
	h := &OIDCHandler{Cfg: &config.Config{OIDCRequireInvite: true}}
	r := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)

	if h.canAutoCreate(r) {
		t.Error("canAutoCreate = true, want false when OIDCRequireInvite is set")
	}
}
