package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/types"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/service"
	"schautrack/internal/session"
)

// seedLoginUser creates a verified password user with no recorded login and
// removes it afterwards. totpSecret != "" enables TOTP with that secret.
func seedLoginUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email, password, totpSecret string) int {
	t.Helper()
	cleanup := func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, email) }
	cleanup()
	t.Cleanup(cleanup)

	var secret any
	if totpSecret != "" {
		secret = totpSecret
	}
	var id int
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, email_verified, totp_enabled, totp_secret)
		 VALUES ($1, $2, true, $3, $4) RETURNING id`,
		email, argon2HashOf(t, password), totpSecret != "", secret).Scan(&id); err != nil {
		t.Fatalf("seeding %s failed: %v", email, err)
	}
	return id
}

func lastLoginAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID int) *time.Time {
	t.Helper()
	var ts *time.Time
	if err := pool.QueryRow(ctx, `SELECT last_login_at FROM users WHERE id = $1`, userID).Scan(&ts); err != nil {
		t.Fatalf("reading last_login_at: %v", err)
	}
	return ts
}

// requireFreshLogin fails unless last_login_at was stamped within the last minute.
func requireFreshLogin(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID int, path string) {
	t.Helper()
	ts := lastLoginAt(t, ctx, pool, userID)
	if ts == nil {
		t.Fatalf("%s: last_login_at is NULL after a successful login", path)
	}
	if d := time.Since(*ts); d < -time.Minute || d > time.Minute {
		t.Fatalf("%s: last_login_at = %v, not within a minute of now", path, *ts)
	}
}

func requireNoLogin(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID int, what string) {
	t.Helper()
	if ts := lastLoginAt(t, ctx, pool, userID); ts != nil {
		t.Fatalf("%s: last_login_at = %v, want NULL (this is not a completed login)", what, *ts)
	}
}

func loginRequest(t *testing.T, data map[string]any, body map[string]string) *http.Request {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := newRequestWithSessionData("/api/auth/login", string(b), data)
	return r
}

func freshLoginTracker(t *testing.T) {
	orig := loginFailures
	loginFailures = newFailureTracker(15*time.Minute, 100)
	t.Cleanup(func() { loginFailures = orig })
}

func TestPasswordLoginRecordsLastLogin(t *testing.T) {
	ctx, pool := inviteTestPool(t)
	freshLoginTracker(t)
	id := seedLoginUser(t, ctx, pool, "lastlogin-pw@handler.test", "the-real-password", "")
	h := &AuthHandler{Pool: pool, SessionStore: session.NewStore(pool), Email: service.NewEmailService(&config.Config{})}

	w := httptest.NewRecorder()
	h.Login(w, loginRequest(t, map[string]any{}, map[string]string{"email": "lastlogin-pw@handler.test", "password": "the-real-password"}))
	if w.Code != http.StatusOK {
		t.Fatalf("login = %d %s, want 200", w.Code, w.Body.String())
	}
	requireFreshLogin(t, ctx, pool, id, "password login")
}

func TestFailedLoginDoesNotRecordLastLogin(t *testing.T) {
	ctx, pool := inviteTestPool(t)
	freshLoginTracker(t)
	id := seedLoginUser(t, ctx, pool, "lastlogin-fail@handler.test", "the-real-password", "")
	h := &AuthHandler{Pool: pool, SessionStore: session.NewStore(pool), Email: service.NewEmailService(&config.Config{})}

	w := httptest.NewRecorder()
	h.Login(w, loginRequest(t, map[string]any{}, map[string]string{"email": "lastlogin-fail@handler.test", "password": "the-wrong-password"}))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-password login = %d %s, want 401", w.Code, w.Body.String())
	}
	requireNoLogin(t, ctx, pool, id, "wrong password")
}

// A correct password on a 2FA account is only half a login: the timestamp is
// written when the code is accepted, not before, and not for a wrong code.
func TestTOTPLoginRecordsLastLoginOnlyAfterTheCode(t *testing.T) {
	ctx, pool := inviteTestPool(t)
	freshLoginTracker(t)
	const secret = "JBSWY3DPEHPK3PXP"
	id := seedLoginUser(t, ctx, pool, "lastlogin-totp@handler.test", "the-real-password", secret)
	h := &AuthHandler{Pool: pool, SessionStore: session.NewStore(pool), Email: service.NewEmailService(&config.Config{})}

	w := httptest.NewRecorder()
	h.Login(w, loginRequest(t, map[string]any{}, map[string]string{"email": "lastlogin-totp@handler.test", "password": "the-real-password"}))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "requireToken") {
		t.Fatalf("password step = %d %s, want 200 requireToken", w.Code, w.Body.String())
	}
	requireNoLogin(t, ctx, pool, id, "password accepted, 2FA pending")

	w = httptest.NewRecorder()
	h.Login(w, loginRequest(t, map[string]any{"pendingUserId": id}, map[string]string{"token": "000000x"}))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong 2FA code = %d %s, want 401", w.Code, w.Body.String())
	}
	requireNoLogin(t, ctx, pool, id, "wrong 2FA code")

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.Login(w, loginRequest(t, map[string]any{"pendingUserId": id}, map[string]string{"token": code}))
	if w.Code != http.StatusOK {
		t.Fatalf("2FA step = %d %s, want 200", w.Code, w.Body.String())
	}
	requireFreshLogin(t, ctx, pool, id, "password + TOTP login")
}

// Registration without SMTP signs the new user straight in — that is their
// first login.
func TestRegisterAutoLoginRecordsLastLogin(t *testing.T) {
	ctx, pool := inviteTestPool(t)
	const email = "lastlogin-register@handler.test"
	cleanup := func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, email) }
	cleanup()
	t.Cleanup(cleanup)

	cfg := &config.Config{EnableRegistration: "open"}
	h := &AuthHandler{Pool: pool, SessionStore: session.NewStore(pool), Email: service.NewEmailService(cfg),
		Cfg: cfg, Settings: database.NewSettingsCache(pool)}
	r, sess := newRequestWithSessionData("/api/auth/register", `{}`, map[string]any{
		"pendingRegistration": map[string]any{"email": email, "hash": argon2HashOf(t, "pw"), "timezone": "UTC", "createdAt": float64(time.Now().Unix())},
		registerCaptchaKey:    "7",
	})
	w := httptest.NewRecorder()
	h.registerCaptcha(w, r, sess, "7")
	if w.Code != http.StatusOK {
		t.Fatalf("register = %d %s, want 200", w.Code, w.Body.String())
	}
	var id int
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&id); err != nil {
		t.Fatalf("registered user not found: %v", err)
	}
	requireFreshLogin(t, ctx, pool, id, "register auto-login")
}

// Entering the email-verification code completes the sign-in.
func TestVerifyEmailLoginRecordsLastLogin(t *testing.T) {
	ctx, pool := inviteTestPool(t)
	const email = "lastlogin-verify@handler.test"
	id := seedLoginUser(t, ctx, pool, email, "pw", "")
	if _, err := pool.Exec(ctx, `UPDATE users SET email_verified = false WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES ($1, '135792', NOW() + INTERVAL '10 minutes')`, id); err != nil {
		t.Fatal(err)
	}
	h := &AuthHandler{Pool: pool, SessionStore: session.NewStore(pool)}

	r, _ := newRequestWithSessionData("/api/auth/verify-email", `{"code":"999999"}`, map[string]any{"verifyEmail": email})
	w := httptest.NewRecorder()
	h.VerifyEmail(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong verification code = %d %s, want 400", w.Code, w.Body.String())
	}
	requireNoLogin(t, ctx, pool, id, "wrong verification code")

	r, _ = newRequestWithSessionData("/api/auth/verify-email", `{"code":"135792"}`, map[string]any{"verifyEmail": email})
	w = httptest.NewRecorder()
	h.VerifyEmail(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("verify email = %d %s, want 200", w.Code, w.Body.String())
	}
	requireFreshLogin(t, ctx, pool, id, "email verification login")
}

// All three OIDC outcomes that end in a session: an already-linked identity,
// an auto-link by verified email, and an auto-created account.
func TestOIDCLoginRecordsLastLogin(t *testing.T) {
	ctx, pool := inviteTestPool(t)
	cfg := &config.Config{EnableRegistration: "open"}
	h := &OIDCHandler{Pool: pool, Cfg: cfg, Settings: database.NewSettingsCache(pool), SessionStore: session.NewStore(pool)}

	call := func(subject, email string) {
		t.Helper()
		r := reqWith(http.MethodGet, "/auth/oidc/callback", newTestSession(), nil)
		w := httptest.NewRecorder()
		h.handleLogin(w, r, session.GetSession(r), "lastlogin-idp", subject, email, true)
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/dashboard" {
			t.Fatalf("OIDC login %s = %d → %q, want 302 → /dashboard", subject, w.Code, w.Header().Get("Location"))
		}
	}

	// Auto-link: an existing password account with the IdP's verified email.
	linkedID := seedLoginUser(t, ctx, pool, "lastlogin-oidc-link@handler.test", "pw", "")
	call("sub-link", "lastlogin-oidc-link@handler.test")
	requireFreshLogin(t, ctx, pool, linkedID, "OIDC auto-link")

	// Already linked: the same identity again, after clearing the stamp.
	if _, err := pool.Exec(ctx, `UPDATE users SET last_login_at = NULL WHERE id = $1`, linkedID); err != nil {
		t.Fatal(err)
	}
	call("sub-link", "lastlogin-oidc-link@handler.test")
	requireFreshLogin(t, ctx, pool, linkedID, "OIDC linked-account login")

	// Auto-create.
	const created = "lastlogin-oidc-new@handler.test"
	cleanup := func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, created) }
	cleanup()
	t.Cleanup(cleanup)
	call("sub-new", created)
	var newID int
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, created).Scan(&newID); err != nil {
		t.Fatalf("auto-created user not found: %v", err)
	}
	requireFreshLogin(t, ctx, pool, newID, "OIDC auto-create")
}

// The passkey ceremony needs a real WebAuthn assertion, so it is covered in
// e2e/passkey.spec.ts. This guard covers it — and any login path added later —
// structurally: every handler that hands out an authenticated session
// (SetUserID(x)) must also stamp the login for that same user
// (recordLogin(ctx, pool, x)), once per SetUserID. Matching the argument, not
// just the call count, is what stops a stamp written to the wrong id — say a
// literal 0, or the pending user of another flow — from passing.
func TestEveryLoginPathRecordsLastLogin(t *testing.T) {
	funcs := parseHandlerPackage(t)
	checked := 0
	for name, fn := range funcs {
		if fn.Body == nil {
			continue
		}
		var sets, records []string
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch f := call.Fun.(type) {
			case *ast.SelectorExpr:
				if f.Sel.Name == "SetUserID" && len(call.Args) == 1 {
					sets = append(sets, types.ExprString(call.Args[0]))
				}
			case *ast.Ident:
				if f.Name == "recordLogin" {
					if len(call.Args) != 3 {
						t.Errorf("%s: recordLogin called with %d args, want (ctx, pool, userID)", name, len(call.Args))
						return true
					}
					records = append(records, types.ExprString(call.Args[2]))
				}
			}
			return true
		})
		if len(sets) == 0 {
			continue
		}
		checked++
		sort.Strings(sets)
		sort.Strings(records)
		if strings.Join(sets, ",") != strings.Join(records, ",") {
			t.Errorf("%s: SetUserID is called for [%s] but recordLogin for [%s]; every new authenticated session must stamp users.last_login_at for that same user",
				name, strings.Join(sets, ", "), strings.Join(records, ", "))
		}
	}
	// Password, password+2FA, register, verify-email, passkey, OIDC: if this
	// drops, the guard stopped seeing the login handlers.
	if checked < 5 {
		t.Fatalf("only %d functions call SetUserID; the AST walk is not seeing the login handlers", checked)
	}
}

func TestAdminUsersOrderBy(t *testing.T) {
	cases := []struct {
		sort, order, want string
		ok                bool
	}{
		{"", "", "created_at DESC, id DESC", true},
		{"created", "", "created_at DESC, id DESC", true},
		{"created", "desc", "created_at DESC, id DESC", true},
		{"last_login", "", "last_login_at DESC NULLS LAST, id DESC", true},
		{"last_login", "desc", "last_login_at DESC NULLS LAST, id DESC", true},
		{"last_login", "asc", "last_login_at ASC NULLS LAST, id DESC", true},
		{"last_login", "sideways", "", false},
		{"created", "asc", "", false},
		{"email; DROP TABLE users", "", "", false},
		{"LAST_LOGIN", "", "", false},
	}
	for _, c := range cases {
		got, ok := adminUsersOrderBy(c.sort, c.order)
		if ok != c.ok || got != c.want {
			t.Errorf("adminUsersOrderBy(%q, %q) = (%q, %v), want (%q, %v)", c.sort, c.order, got, ok, c.want, c.ok)
		}
	}
}

type adminUserRow struct {
	ID          int        `json:"id"`
	Email       string     `json:"email"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

func TestAdminUserListSortsByLastLogin(t *testing.T) {
	ctx, pool := inviteTestPool(t)
	const admin = "lastlogin-admin@handler.test"
	adminID := seedLoginUser(t, ctx, pool, admin, "pw", "")

	// Created in this order (so the default newest-first order is d, c, b, a),
	// with logins that order them differently: b most recent, then d, and a/c
	// never recorded.
	now := time.Now().UTC().Truncate(time.Second)
	logins := map[string]*time.Time{"a": nil, "b": ptrTime(now.Add(-1 * time.Hour)), "c": nil, "d": ptrTime(now.Add(-72 * time.Hour))}
	ids := map[string]int{}
	for i, k := range []string{"a", "b", "c", "d"} {
		email := "lastlogin-sort-" + k + "@handler.test"
		id := seedLoginUser(t, ctx, pool, email, "pw", "")
		if _, err := pool.Exec(ctx, `UPDATE users SET created_at = $2, last_login_at = $3 WHERE id = $1`,
			id, now.Add(time.Duration(i-10)*time.Minute), logins[k]); err != nil {
			t.Fatal(err)
		}
		ids[k] = id
	}

	list := func(query string) (int, []string, map[string]*time.Time) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/admin"+query, nil)
		r = r.WithContext(middleware.WithTestUser(r.Context(), &model.User{ID: adminID, Email: admin}))
		w := httptest.NewRecorder()
		AdminData(pool, database.NewSettingsCache(pool), admin).ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			return w.Code, nil, nil
		}
		var resp struct {
			Users []adminUserRow `json:"users"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decoding %s: %v", query, err)
		}
		var order []string
		seen := map[string]*time.Time{}
		for _, u := range resp.Users {
			for k, id := range ids {
				if u.ID == id {
					order = append(order, k)
					seen[k] = u.LastLoginAt
				}
			}
		}
		return w.Code, order, seen
	}

	for _, c := range []struct{ query, want string }{
		{"", "dcba"},                            // default order unchanged
		{"?sort=last_login", "bdca"},            // most recent first, unknowns last
		{"?sort=last_login&order=desc", "bdca"}, // explicit desc
		{"?sort=last_login&order=asc", "dbca"},  // longest-ago first, unknowns still last
	} {
		code, order, seen := list(c.query)
		if code != http.StatusOK {
			t.Fatalf("GET /api/admin%s = %d, want 200", c.query, code)
		}
		if got := strings.Join(order, ""); got != c.want {
			t.Errorf("GET /api/admin%s order = %q, want %q", c.query, got, c.want)
		}
		for k, want := range logins {
			got := seen[k]
			if (got == nil) != (want == nil) || (got != nil && !got.Equal(*want)) {
				t.Errorf("GET /api/admin%s user %s last_login_at = %v, want %v", c.query, k, got, want)
			}
		}
	}

	for _, q := range []string{"?sort=nope", "?sort=last_login&order=up"} {
		if code, _, _ := list(q); code != http.StatusBadRequest {
			t.Errorf("GET /api/admin%s = %d, want 400", q, code)
		}
	}
}

// The admin list is the only place last_login_at is served. The route's
// middleware chain must refuse a signed-in non-admin before AdminData runs,
// with nothing about other users in the body.
func TestAdminUserListForbiddenForNonAdmin(t *testing.T) {
	ctx, pool := inviteTestPool(t)
	const admin = "lastlogin-admin2@handler.test"
	seedLoginUser(t, ctx, pool, admin, "pw", "")
	userID := seedLoginUser(t, ctx, pool, "lastlogin-nonadmin@handler.test", "pw", "")
	if _, err := pool.Exec(ctx, `UPDATE users SET last_login_at = NOW() WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}

	route := middleware.RequireAdmin(admin)(AdminData(pool, database.NewSettingsCache(pool), admin))
	for _, u := range []*model.User{{ID: userID, Email: "lastlogin-nonadmin@handler.test"}, nil} {
		r := httptest.NewRequest(http.MethodGet, "/api/admin?sort=last_login", nil)
		if u != nil {
			r = r.WithContext(middleware.WithTestUser(r.Context(), u))
		}
		w := httptest.NewRecorder()
		route.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("GET /api/admin as %v = %d, want 403", u, w.Code)
		}
		if strings.Contains(w.Body.String(), "last_login_at") || strings.Contains(w.Body.String(), "@handler.test") {
			t.Errorf("403 body leaks user data: %s", w.Body.String())
		}
	}
}

// last_login_at is admin-only: it must not ride along on the user model that
// /api/me, /api/v1/me and the account export serialise.
func TestLastLoginNotOnUserModel(t *testing.T) {
	b, err := json.Marshal(model.User{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	_ = json.Unmarshal(b, &fields)
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.Contains(strings.ToLower(k), "login") {
			t.Errorf("model.User serialises %q; last-login data is admin-only (fields: %s)", k, fmt.Sprint(keys))
		}
	}
}
