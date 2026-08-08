package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/service"
)

// =============================================================================
// Issue #342 — the invite email goes through the same validator as every other
// address that enters the system.
// =============================================================================

// A malformed invite address must be rejected before anything is written.
// The nil Pool is the assertion that no row is created: CreateInvite's only
// statement is the INSERT, so reaching it would panic instead of returning
// 400. The nil Email service makes the same point for the send path.
//
// Before the fix every one of these produced a 200, a stored row, and an
// invite code that no registrant could ever redeem — registerCredentials
// compares the stored address against the canonical form validateEmail
// returns, and none of these can equal a canonical address.
func TestCreateInvite_RejectsInvalidEmail(t *testing.T) {
	bad := []struct {
		email string
		why   string
	}{
		{"a", "no @, no domain"},
		{"not an email", "prose — the shape from the issue"},
		{"<script>", "markup"},
		{"a@", "no domain"},
		{"@b.com", "no local part"},
		{"a b@c.com", "unquoted space"},
		{"Foo <a@b.com>", "display-name form is not a bare address"},
		{"a@b.com\nBcc: x@y.com", "SMTP header injection shape"},
		{"a@b.com\r\nBcc: x@y.com", "SMTP header injection shape"},
		{emailLocal64 + "@" + strings.Repeat("b", 931) + ".com", "over the RFC 5321 cap"},
		{strings.Repeat("x", 5<<20) + "@example.com", "five megabytes"},
	}
	for _, tt := range bad {
		h := &AdminHandler{
			Pool:  nil, // must not be touched — no invite row may be written
			Cfg:   &config.Config{},
			Email: nil, // must not be touched — nothing may be sent
		}
		body, _ := json.Marshal(map[string]any{"email": tt.email})
		r := httptest.NewRequest(http.MethodPost, "/admin/invites", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r = r.WithContext(middleware.WithTestUser(r.Context(), &model.User{ID: 1, Email: "admin@example.com"}))
		w := httptest.NewRecorder()

		h.CreateInvite(w, r)

		label := tt.email
		if len(label) > 40 {
			label = label[:40] + "…"
		}
		if w.Code != http.StatusBadRequest {
			t.Errorf("email %q (%s): status = %d, want %d", label, tt.why, w.Code, http.StatusBadRequest)
			continue
		}
		var resp map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp)
		if msg, _ := resp["error"].(string); msg == "" {
			t.Errorf("email %q: 400 carried no error message (%v); the admin has to be told why", label, resp)
		}
	}
}

// The rejection must not be a blanket one: a valid address has to get past the
// validator and reach the INSERT. A nil Pool panics there, which is exactly
// the signal we want — it proves the handler did not bail out early.
func TestCreateInvite_ValidEmailReachesTheInsert(t *testing.T) {
	for _, email := range []string{"a@b.com", "  Foo.Bar@Example.COM  ", "a@b"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("email %q: CreateInvite returned without touching the pool; a valid address must reach the INSERT", email)
				}
			}()
			h := &AdminHandler{Pool: nil, Cfg: &config.Config{}}
			body, _ := json.Marshal(map[string]any{"email": email})
			r := httptest.NewRequest(http.MethodPost, "/admin/invites", strings.NewReader(string(body)))
			r.Header.Set("Content-Type", "application/json")
			r = r.WithContext(middleware.WithTestUser(r.Context(), &model.User{ID: 1, Email: "admin@example.com"}))
			h.CreateInvite(httptest.NewRecorder(), r)
		}()
	}
}

// An invite with no email at all is the common case (a shareable code) and
// must stay allowed — it reaches the INSERT with a NULL email.
func TestCreateInvite_EmptyEmailIsStillAllowed(t *testing.T) {
	for _, body := range []string{`{}`, `{"email":""}`, `{"email":"   "}`} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("body %s: CreateInvite bailed out; an invite without an email must still be created", body)
				}
			}()
			h := &AdminHandler{Pool: nil, Cfg: &config.Config{}}
			r := httptest.NewRequest(http.MethodPost, "/admin/invites", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r = r.WithContext(middleware.WithTestUser(r.Context(), &model.User{ID: 1, Email: "admin@example.com"}))
			h.CreateInvite(httptest.NewRecorder(), r)
		}()
	}
}

// canonicalizeEmail is what makes the read side of the invite comparison agree
// with the write side. It must be exactly validateEmail's normalization, with
// no validation — a legacy row must be brought into canonical form, never
// rejected.
func TestCanonicalizeEmailMatchesValidateEmail(t *testing.T) {
	// Anything validateEmail accepts, canonicalizeEmail must map to the same
	// string, or a freshly created invite would not match its own registrant.
	accepted := []string{
		"a@b.com", "  A@B.COM  ", "Foo.Bar@Example.COM", "a@b",
		"a.user+tag@example.com", "\tMiXeD@CaSe.Org\n",
	}
	for _, in := range accepted {
		want, err := validateEmail(in)
		if err != nil {
			t.Fatalf("fixture %q is supposed to be valid: %v", in, err)
		}
		if got := canonicalizeEmail(in); got != want {
			t.Errorf("canonicalizeEmail(%q) = %q, want %q (validateEmail's form)", in, got, want)
		}
	}

	// And it must not reject: a legacy row holding garbage still has to
	// produce a comparable string rather than an error or an empty one.
	if got := canonicalizeEmail("  Not An Email  "); got != "not an email" {
		t.Errorf("canonicalizeEmail(%q) = %q; it must normalize, not validate", "  Not An Email  ", got)
	}
	if got := canonicalizeEmail("   "); got != "" {
		t.Errorf("canonicalizeEmail(whitespace) = %q, want \"\" so the caller treats it as an unbound invite", got)
	}
}

// =============================================================================
// Integration: the stored form, and redemption against it.
//
// Skipped unless TEST_DATABASE_URL is set, matching the other integration
// tests in this package. CI has Postgres since #325, so these do run there.
//
//	TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./internal/handler/ -run Invite -v
//
// =============================================================================

func inviteTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	pool, err := database.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return ctx, pool
}

// seedAdmin creates the user the invite is attributed to (created_by is a FK)
// and removes it, and everything it owns, afterwards.
func seedAdmin(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) int {
	t.Helper()
	cleanup := func() {
		pool.Exec(ctx, `DELETE FROM invite_codes WHERE created_by IN (SELECT id FROM users WHERE email = $1)`, email)
		pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, email)
	}
	cleanup()
	t.Cleanup(cleanup)

	var id int
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, email_verified) VALUES ($1, 'x', true) RETURNING id`,
		email).Scan(&id); err != nil {
		t.Fatalf("seeding the admin failed: %v", err)
	}
	return id
}

// A mixed-case, padded address must be STORED lowercase and trimmed — not
// merely compared leniently later. The stored form is what ListInvites shows
// the admin and what SendInviteEmail hands to the SMTP server.
func TestCreateInvite_StoresCanonicalEmail(t *testing.T) {
	ctx, pool := inviteTestPool(t)
	adminID := seedAdmin(t, ctx, pool, "invite-canonical-admin@handler.test")

	h := &AdminHandler{
		Pool:     pool,
		Settings: database.NewSettingsCache(pool),
		Cfg:      &config.Config{},
		// SMTP deliberately unconfigured: IsConfigured() is false, so the
		// test asserts the stored form without talking to a mail server.
		Email: service.NewEmailService(&config.Config{}),
	}

	cases := []struct {
		in   string
		want any // string, or nil for a code with no bound address
	}{
		{"  Foo.Bar@Example.COM  ", "foo.bar@example.com"},
		{"ALLCAPS@EXAMPLE.ORG", "allcaps@example.org"},
		{"already@canonical.test", "already@canonical.test"},
		{"", nil},
		{"   ", nil},
	}
	for _, tc := range cases {
		body, _ := json.Marshal(map[string]any{"email": tc.in})
		r := httptest.NewRequest(http.MethodPost, "/admin/invites", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r = r.WithContext(middleware.WithTestUser(ctx, &model.User{ID: adminID, Email: "invite-canonical-admin@handler.test"}))
		w := httptest.NewRecorder()

		h.CreateInvite(w, r)

		if w.Code != http.StatusOK {
			t.Fatalf("email %q: status = %d, want 200 (body %s)", tc.in, w.Code, w.Body.String())
		}
		var resp struct {
			OK     bool `json:"ok"`
			Invite struct {
				ID    int     `json:"id"`
				Code  string  `json:"code"`
				Email *string `json:"email"`
			} `json:"invite"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("email %q: response is not JSON: %v", tc.in, err)
		}

		var stored *string
		if err := pool.QueryRow(ctx, `SELECT email FROM invite_codes WHERE id = $1`, resp.Invite.ID).Scan(&stored); err != nil {
			t.Fatalf("email %q: reading the row back failed: %v", tc.in, err)
		}

		if tc.want == nil {
			if stored != nil {
				t.Errorf("email %q: stored %q, want NULL (an unbound invite)", tc.in, *stored)
			}
			continue
		}
		if stored == nil {
			t.Errorf("email %q: stored NULL, want %q", tc.in, tc.want)
			continue
		}
		if *stored != tc.want {
			t.Errorf("email %q: stored %q, want %q — a non-canonical row can never match the registrant", tc.in, *stored, tc.want)
		}
		// The response must show the admin the same thing the database holds.
		if resp.Invite.Email == nil || *resp.Invite.Email != *stored {
			t.Errorf("email %q: response email = %v, stored = %q; they must agree", tc.in, resp.Invite.Email, *stored)
		}
	}
}

// The end-to-end point of the issue: an invite created with a mixed-case
// address is redeemable by the registrant typing the same address in any case.
//
// Also pins the legacy half. A row written before the fix — mixed case, and in
// the padded shape only a direct write could produce — must still redeem,
// because the comparison canonicalizes the stored side rather than trusting it.
func TestInviteRedemption_MixedCaseInviteIsRedeemable(t *testing.T) {
	ctx, pool := inviteTestPool(t)
	adminID := seedAdmin(t, ctx, pool, "invite-redeem-admin@handler.test")

	settings := database.NewSettingsCache(pool)
	admin := &AdminHandler{
		Pool: pool, Settings: settings, Cfg: &config.Config{},
		Email: service.NewEmailService(&config.Config{}),
	}
	auth := &AuthHandler{
		Pool:     pool,
		Cfg:      &config.Config{EnableRegistration: "invite"},
		Settings: settings,
	}

	// Make sure no leftover account blocks the "already exists" check.
	const registrant = "invitee.person@example.com"
	pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, registrant)
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, registrant) })

	// (1) An invite created through the handler with a mixed-case address.
	body, _ := json.Marshal(map[string]any{"email": "  Invitee.Person@Example.COM  "})
	cr := httptest.NewRequest(http.MethodPost, "/admin/invites", strings.NewReader(string(body)))
	cr.Header.Set("Content-Type", "application/json")
	cr = cr.WithContext(middleware.WithTestUser(ctx, &model.User{ID: adminID, Email: "invite-redeem-admin@handler.test"}))
	cw := httptest.NewRecorder()
	admin.CreateInvite(cw, cr)
	if cw.Code != http.StatusOK {
		t.Fatalf("creating the invite: status = %d (body %s)", cw.Code, cw.Body.String())
	}
	var created struct {
		Invite struct {
			Code string `json:"code"`
		} `json:"invite"`
	}
	json.Unmarshal(cw.Body.Bytes(), &created)
	if created.Invite.Code == "" {
		t.Fatalf("no invite code in the response: %s", cw.Body.String())
	}

	// (2) A legacy row in the pre-fix shape, written straight to the table.
	var legacyCode string
	if err := pool.QueryRow(ctx,
		`INSERT INTO invite_codes (code, email, created_by, expires_at)
		 VALUES ($1, $2, $3, NOW() + INTERVAL '14 days') RETURNING code`,
		"legacy-mixed-case-342", "  Invitee.Person@Example.COM  ", adminID).Scan(&legacyCode); err != nil {
		t.Fatalf("seeding the legacy invite failed: %v", err)
	}

	redeem := func(code, email string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]any{
			"step": "credentials", "email": email,
			"password": "longenoughpassword", "timezone": "UTC",
			"invite_code": code,
		})
		r := newRequestWithSession(http.MethodPost, "/api/auth/register", string(b))
		w := httptest.NewRecorder()
		auth.Register(w, r)
		return w
	}

	for _, tc := range []struct {
		name  string
		code  string
		email string
	}{
		{"handler-created invite, canonical registrant", created.Invite.Code, registrant},
		{"handler-created invite, registrant types mixed case", created.Invite.Code, "Invitee.Person@Example.COM"},
		{"legacy non-canonical row still redeems", legacyCode, registrant},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := redeem(tc.code, tc.email)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (the invite gate must pass) — body %s", w.Code, w.Body.String())
			}
			var resp map[string]any
			json.Unmarshal(w.Body.Bytes(), &resp)
			if ok, _ := resp["ok"].(bool); !ok {
				t.Fatalf("body = %v, want ok:true", resp)
			}
			if req, _ := resp["requireCaptcha"].(bool); !req {
				t.Errorf("body = %v, want requireCaptcha:true — the flow must have reached the captcha step", resp)
			}
		})
	}

	// The negative case must still hold: a genuinely different address is
	// rejected, so the canonicalization is not just accepting everything.
	w := redeem(created.Invite.Code, "someone.else@example.com")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("a different address: status = %d, want 400", w.Code)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "different email address") {
		t.Errorf("error = %q, want the bound-address rejection", msg)
	}
}
