package handler

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/session"
)

// Tests for issue #340: the password *verification* paths (login, the
// 2FA-reset request, step-up re-authentication) must never hand an unbounded
// client-supplied string to argon2id, and the rejection must not be
// observable to the client.

// recordArgon2Compare swaps argon2Compare for a recorder and returns the
// recorded plaintext arguments. The seam is the only way to assert what
// reached the KDF; a wall-clock measurement cannot distinguish "hashed 4 KB"
// from "hashed 4 KB + 1 byte".
func recordArgon2Compare(t *testing.T, result bool) *[]string {
	t.Helper()
	var seen []string
	orig := argon2Compare
	argon2Compare = func(password, hash string) (bool, error) {
		seen = append(seen, password)
		return result, nil
	}
	t.Cleanup(func() { argon2Compare = orig })
	return &seen
}

func argon2HashOf(t *testing.T, password string) string {
	t.Helper()
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		t.Fatalf("argon2id.CreateHash: %v", err)
	}
	return hash
}

// TestVerifyPasswordNeverHashesAnOversizedPassword is the core assertion of
// #340. The submitted string must not reach argon2id — but exactly one
// verification must still run, or the early return becomes a stopwatch signal.
func TestVerifyPasswordNeverHashesAnOversizedPassword(t *testing.T) {
	// Precompute the dummy hash outside the seam so burnPasswordVerifyCost
	// finds it already built.
	if dummyPasswordHash() == "" {
		t.Fatal("dummy password hash unavailable")
	}

	seen := recordArgon2Compare(t, false)

	oversized := strings.Repeat("a", MaxVerifyPasswordBytes+1)
	valid, err := verifyPassword("$argon2id$v=19$m=65536,t=1,p=2$c2FsdHNhbHQ$aGFzaGhhc2g", oversized)
	if err != nil {
		t.Fatalf("verifyPassword returned an error: %v", err)
	}
	if valid {
		t.Fatal("an over-long password verified")
	}

	if len(*seen) != 1 {
		t.Fatalf("argon2id invoked %d times, want exactly 1 (0 = a timing oracle, 2 = wasted work)", len(*seen))
	}
	got := (*seen)[0]
	if got == oversized {
		t.Fatal("the oversized password was handed to argon2id — the whole point of #340")
	}
	if len(got) > MaxVerifyPasswordBytes {
		t.Errorf("argon2id received %d bytes, cap is %d", len(got), MaxVerifyPasswordBytes)
	}
	if got != oversizedPasswordStandIn {
		t.Errorf("argon2id received %q, want the fixed stand-in", got)
	}
}

// TestEqualizeLoginTimingNeverHashesAnOversizedPassword covers the branch an
// attacker reaches without an account: Login calls equalizeLoginTiming when
// the email matches no row, so this is the cheapest path to the KDF.
func TestEqualizeLoginTimingNeverHashesAnOversizedPassword(t *testing.T) {
	if dummyPasswordHash() == "" {
		t.Fatal("dummy password hash unavailable")
	}
	seen := recordArgon2Compare(t, false)

	oversized := strings.Repeat("b", 8<<20) // 8 MB
	equalizeLoginTiming(oversized)

	if len(*seen) != 1 {
		t.Fatalf("argon2id invoked %d times, want exactly 1", len(*seen))
	}
	if len((*seen)[0]) > MaxVerifyPasswordBytes {
		t.Errorf("equalizeLoginTiming handed argon2id %d bytes, cap is %d", len((*seen)[0]), MaxVerifyPasswordBytes)
	}
}

// TestEqualizeLoginTimingStillHashesWhatWasSubmitted pins the other half: for
// a password within the cap, the *submitted* string is hashed, not a
// stand-in. Substituting unconditionally would make the unknown-email branch
// cost a constant while the known-email branch scales with the password — the
// enumeration oracle equalizeLoginTiming exists to close.
func TestEqualizeLoginTimingStillHashesWhatWasSubmitted(t *testing.T) {
	if dummyPasswordHash() == "" {
		t.Fatal("dummy password hash unavailable")
	}
	seen := recordArgon2Compare(t, false)

	equalizeLoginTiming("a-normal-password")

	if len(*seen) != 1 || (*seen)[0] != "a-normal-password" {
		t.Errorf("argon2id received %q, want the submitted password", *seen)
	}
}

// TestVerifyPasswordCapBoundary pins the exact edge: MaxVerifyPasswordBytes
// still verifies against a real hash, one byte more does not.
func TestVerifyPasswordCapBoundary(t *testing.T) {
	atCap := strings.Repeat("z", MaxVerifyPasswordBytes)
	hash := argon2HashOf(t, atCap)

	valid, err := verifyPassword(hash, atCap)
	if err != nil {
		t.Fatalf("verifyPassword at the cap: %v", err)
	}
	if !valid {
		t.Errorf("a %d-byte password (exactly the cap) failed to verify", MaxVerifyPasswordBytes)
	}

	valid, err = verifyPassword(hash, atCap+"z")
	if err != nil {
		t.Fatalf("verifyPassword one byte over the cap: %v", err)
	}
	if valid {
		t.Error("a password one byte over the cap verified")
	}
}

// TestVerifyCapIsAboveTheWritePolicy is the lockout guard. Every path that
// writes a password hash runs validatePassword (MaxPasswordBytes); as long as
// the verify cap sits strictly above it, no password that can be *set* can
// ever be rejected at login. Lowering MaxVerifyPasswordBytes to
// MaxPasswordBytes would still hold here — the margin is the point, so assert
// it explicitly.
func TestVerifyCapIsAboveTheWritePolicy(t *testing.T) {
	if MaxVerifyPasswordBytes <= MaxPasswordBytes {
		t.Fatalf("MaxVerifyPasswordBytes (%d) must exceed MaxPasswordBytes (%d): a password the "+
			"server accepts on a write must always be accepted on a login",
			MaxVerifyPasswordBytes, MaxPasswordBytes)
	}
	if MaxVerifyPasswordBytes < 4*MaxPasswordBytes {
		t.Errorf("MaxVerifyPasswordBytes (%d) dropped below 4x the write policy (%d); #340 chose the "+
			"margin because a password's length is not recoverable from its argon2id hash, so "+
			"grandfathered accounts cannot be surveyed",
			MaxVerifyPasswordBytes, 4*MaxPasswordBytes)
	}

	// And the write validator must actually reject anything the verify cap
	// would later refuse.
	if err := validatePassword(strings.Repeat("q", MaxVerifyPasswordBytes)); err == nil {
		t.Error("validatePassword accepted a password the login cap rejects — that is the lockout bug")
	}
}

// TestOversizedPasswordIsIndistinguishableFromAWrongOne is the no-oracle
// assertion. An attacker submitting an over-long password must not be able to
// tell — by duration — that they hit a special branch, on either the
// known-email path (verifyPassword) or the unknown-email path
// (equalizeLoginTiming). Both must cost one argon2id verification.
func TestOversizedPasswordIsIndistinguishableFromAWrongOne(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement; skipped under -short")
	}
	if dummyPasswordHash() == "" {
		t.Fatal("dummy password hash unavailable")
	}

	hash := argon2HashOf(t, "the-real-password")
	oversized := strings.Repeat("c", MaxVerifyPasswordBytes+1)

	wrong := medianDuration(func() { verifyPassword(hash, "the-wrong-password") })
	tooLong := medianDuration(func() { verifyPassword(hash, oversized) })
	unknownEmail := medianDuration(func() { equalizeLoginTiming(oversized) })

	t.Logf("wrong password          %v", wrong)
	t.Logf("over-long password      %v", tooLong)
	t.Logf("over-long, unknown email %v", unknownEmail)

	// A fast path is the tell. Anything under a third of a real verification
	// means the cap short-circuited without paying the cost.
	floor := wrong / 3
	if tooLong < floor {
		t.Errorf("over-long password returned in %v vs %v for a wrong password: the early return "+
			"skipped the argon2id cost and is a timing oracle", tooLong, wrong)
	}
	if unknownEmail < floor {
		t.Errorf("over-long password on the unknown-email path returned in %v vs %v: "+
			"account-existence oracle", unknownEmail, wrong)
	}
}

// TestOversizedPasswordDoesNotScaleWithItsLength demonstrates the fix against
// the vulnerability itself: before the cap, hashing cost grew with the
// submitted string (argon2id's Blake2b pre-hash is linear in input size).
// After it, a 16 MB password costs no more than a 4 KB one, while hashing the
// 16 MB string directly still does.
func TestOversizedPasswordDoesNotScaleWithItsLength(t *testing.T) {
	if testing.Short() {
		t.Skip("timing measurement; skipped under -short")
	}
	dummy := dummyPasswordHash()
	if dummy == "" {
		t.Fatal("dummy password hash unavailable")
	}

	small := strings.Repeat("d", MaxVerifyPasswordBytes+1)
	huge := strings.Repeat("d", 64<<20) // 64 MB

	guardedSmall := medianDuration(func() { equalizeLoginTiming(small) })
	guardedHuge := medianDuration(func() { equalizeLoginTiming(huge) })
	// What the same request cost before the cap existed.
	unguardedHuge := medianDuration(func() { argon2id.ComparePasswordAndHash(huge, dummy) })

	t.Logf("guarded, %9d bytes: %v", len(small), guardedSmall)
	t.Logf("guarded, %9d bytes: %v", len(huge), guardedHuge)
	t.Logf("UNGUARDED (pre-fix), %d bytes: %v", len(huge), unguardedHuge)

	// All three numbers come from the same run, so the decision line scales
	// with the machine instead of being a hardcoded millisecond budget: the
	// guarded 64 MB attempt must land nearer the small-input cost than the
	// unguarded one. Deleting the cap moves it to the far side.
	midpoint := (guardedSmall + unguardedHuge) / 2
	if guardedHuge > midpoint {
		t.Errorf("guarded cost grew with the password: %v at 64 MB, vs %v at %d bytes and %v "+
			"unguarded (decision line %v) — something is still hashing the full string",
			guardedHuge, guardedSmall, len(small), unguardedHuge, midpoint)
	}
}

// medianDuration times f five times after a warm-up run and returns the
// median, so a single scheduler hiccup cannot decide a timing assertion.
func medianDuration(f func()) time.Duration {
	f() // warm up: first argon2id call also builds the dummy hash
	const n = 5
	samples := make([]time.Duration, n)
	for i := range samples {
		start := time.Now()
		f()
		samples[i] = time.Since(start)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples[n/2]
}

// TestVerifyPathsGoThroughTheCap is the structural half, in the style of
// TestCredentialValidatorsGateEveryWrite. verifyPassword is the choke point
// for every stored-hash comparison; a future handler that reaches for
// argon2id directly would silently reopen #340.
func TestVerifyPathsGoThroughTheCap(t *testing.T) {
	funcs := parseHandlerPackage(t)

	for _, name := range []string{"verifyPassword", "equalizeLoginTiming"} {
		fn, ok := funcs[name]
		if !ok {
			t.Errorf("%s not found — was it renamed? The verify cap must follow it", name)
			continue
		}
		if !funcCallsIdent(fn, "passwordExceedsVerifyCap") {
			t.Errorf("%s does not call passwordExceedsVerifyCap; it would hand an unbounded "+
				"client-supplied string to argon2id (#340)", name)
		}
	}

	// The three verification paths named in #340 must reach the hash through
	// verifyPassword, which is where the cap lives. These are looked up by
	// receiver, not by bare name: the package has two methods called Login
	// (AuthHandler and OIDCHandler) and a bare-name map silently keeps
	// whichever file parses last.
	methods := parseHandlerMethods(t)
	for _, name := range []string{
		"AuthHandler.Login",          // auth.go — password login
		"AuthHandler.Reset2FA",       // auth_helpers.go — the "request" step
		"StepUpHandler.PasswordTOTP", // stepup.go — step-up re-authentication
	} {
		fn, ok := methods[name]
		if !ok {
			t.Errorf("%s not found — was it renamed?", name)
			continue
		}
		if !funcCallsIdent(fn, "verifyPassword") {
			t.Errorf("%s no longer checks the password through verifyPassword; it would bypass "+
				"the #340 length cap", name)
		}
	}

	// The set of handler functions allowed to touch a password hash function
	// at all. Anything else must go through verifyPassword.
	allowed := map[string]string{
		"verifyPassword":         "the capped choke point",
		"burnPasswordVerifyCost": "pays the cost with a bounded stand-in",
		"hashPassword":           "write path, gated by validatePassword",
		"dummyPasswordHash":      "precomputes a constant, no client input",
	}
	var offenders []string
	for name, fn := range funcs {
		if _, ok := allowed[name]; ok {
			continue
		}
		if funcCallsIdent(fn, "argon2Compare") || funcCallsPackage(fn, "argon2id") || funcCallsPackage(fn, "bcrypt") {
			offenders = append(offenders, name)
		}
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("these functions reach a password hash function directly instead of via "+
			"verifyPassword, bypassing the #340 length cap: %v", offenders)
	}
}

// TestLoginOversizedPasswordIsIndistinguishableEndToEnd is the same no-oracle
// property asserted through the real HTTP handler rather than the helper: the
// status line and response body for an over-long password must be byte-identical
// to those for a wrong password, on both the known-email and the unknown-email
// branch. If they ever diverge, an unauthenticated attacker gains a probe.
//
// Skipped unless TEST_DATABASE_URL is set, matching the other integration
// tests in this package.
func TestLoginOversizedPasswordIsIndistinguishableEndToEnd(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	const email = "verify-cap@handler.test"
	cleanup := func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, email) }
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx,
		`INSERT INTO users (email, password_hash, email_verified) VALUES ($1, $2, true)`,
		email, argon2HashOf(t, "the-real-password")); err != nil {
		t.Fatalf("seeding the user failed: %v", err)
	}

	// Every attempt must start from zero recorded failures, or the third one
	// gets a captcha challenge and the bodies stop being comparable.
	origTracker := loginFailures
	t.Cleanup(func() { loginFailures = origTracker })

	oversized := strings.Repeat("e", MaxVerifyPasswordBytes+1)
	attempt := func(email, password string) (int, string) {
		loginFailures = newFailureTracker(15*time.Minute, 100)
		// encoding/json, not fmt: a multi-kilobyte password must be escaped.
		body, err := json.Marshal(map[string]string{"email": email, "password": password})
		if err != nil {
			t.Fatalf("marshalling the login body: %v", err)
		}
		r := newRequestWithSession("POST", "/api/auth/login", string(body))
		w := httptest.NewRecorder()
		(&AuthHandler{Pool: pool}).Login(w, r)
		return w.Code, w.Body.String()
	}

	cases := []struct {
		name           string
		email, passwrd string
	}{
		{"known email, wrong password", email, "the-wrong-password"},
		{"known email, over-long password", email, oversized},
		{"unknown email, wrong password", "no-such-user@handler.test", "the-wrong-password"},
		{"unknown email, over-long password", "no-such-user@handler.test", oversized},
	}

	wantCode, wantBody := attempt(cases[0].email, cases[0].passwrd)
	if wantCode != http.StatusUnauthorized {
		t.Fatalf("baseline wrong-password attempt returned %d, want 401 (body %s)", wantCode, wantBody)
	}
	t.Logf("baseline (%s): %d %s", cases[0].name, wantCode, wantBody)

	for _, c := range cases[1:] {
		code, body := attempt(c.email, c.passwrd)
		t.Logf("%-34s: %d %s", c.name, code, body)
		if code != wantCode || body != wantBody {
			t.Errorf("%s produced %d %q; the wrong-password baseline is %d %q — that difference "+
				"is an oracle", c.name, code, body, wantCode, wantBody)
		}
	}
}

// TestStepUpOversizedPasswordIsIndistinguishableEndToEnd covers the third
// verification path from #340. Step-up is authenticated, so it is not an
// enumeration surface — but it is still a place where an over-long password
// used to reach argon2id, and its rejection must look exactly like a wrong
// password so it cannot be used to probe the cap's existence or value.
//
// Skipped unless TEST_DATABASE_URL is set.
func TestStepUpOversizedPasswordIsIndistinguishableEndToEnd(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	if err := database.InitSchemaWithRetry(ctx, pool, 1); err != nil {
		t.Fatalf("migrations: %v", err)
	}

	const email = "verify-cap-stepup@handler.test"
	cleanup := func() { pool.Exec(ctx, `DELETE FROM users WHERE email = $1`, email) }
	cleanup()
	t.Cleanup(cleanup)

	var userID int
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, email_verified) VALUES ($1, $2, true) RETURNING id`,
		email, argon2HashOf(t, "the-real-password")).Scan(&userID); err != nil {
		t.Fatalf("seeding the user failed: %v", err)
	}

	h := &StepUpHandler{Pool: pool}
	attempt := func(password string) (int, string, bool) {
		body, err := json.Marshal(map[string]string{"password": password})
		if err != nil {
			t.Fatalf("marshalling the step-up body: %v", err)
		}
		// A fresh session per attempt, so both are failure #1 and the
		// lockout counter cannot make the two responses differ.
		r := newRequestWithSession("POST", "/api/auth/step-up", string(body))
		sess := session.GetSession(r)
		r = r.WithContext(middleware.WithTestUser(r.Context(), &model.User{ID: userID, Email: email}))
		r = r.WithContext(session.WithTestSession(r.Context(), sess))
		w := httptest.NewRecorder()
		h.PasswordTOTP(w, r)
		return w.Code, w.Body.String(), sess.HasRecentStepUp()
	}

	wantCode, wantBody, wantFresh := attempt("the-wrong-password")
	t.Logf("wrong password    : %d %s (stepUpFresh=%v)", wantCode, wantBody, wantFresh)
	if wantCode != http.StatusUnauthorized {
		t.Fatalf("baseline wrong-password step-up returned %d, want 401 (body %s)", wantCode, wantBody)
	}
	if wantFresh {
		t.Fatal("a wrong password granted step-up")
	}

	code, body, fresh := attempt(strings.Repeat("f", MaxVerifyPasswordBytes+1))
	t.Logf("over-long password: %d %s (stepUpFresh=%v)", code, body, fresh)
	if code != wantCode || body != wantBody {
		t.Errorf("over-long password produced %d %q; the wrong-password baseline is %d %q",
			code, body, wantCode, wantBody)
	}
	if fresh {
		t.Error("an over-long password granted step-up")
	}
}

// parseHandlerMethods is parseHandlerPackage keyed by "Receiver.Method"
// instead of by bare method name. The bare-name map cannot express
// "AuthHandler.Login" — the package also has OIDCHandler.Login, and whichever
// file the parser reaches last wins — so a guard written against "Login" may
// be asserting on the wrong function without saying so.
func parseHandlerMethods(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the handler package directory: %v", err)
	}
	fset := token.NewFileSet()
	methods := map[string]*ast.FuncDecl{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) == 0 {
				continue
			}
			recv := fd.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			id, ok := recv.(*ast.Ident)
			if !ok {
				continue
			}
			methods[id.Name+"."+fd.Name.Name] = fd
		}
	}
	if len(methods) == 0 {
		t.Fatal("no methods parsed from the handler package — the test is not looking at real code")
	}
	return methods
}

// funcCallsPackage reports whether fn's body contains a call to any function
// in the named package (pkg.Anything).
func funcCallsPackage(fn *ast.FuncDecl, pkg string) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == pkg {
			found = true
		}
		return true
	})
	return found
}
