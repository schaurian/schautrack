package handler

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
)

func TestRegistrationMode(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"empty is open", "", regModeOpen},
		{"open is open", "open", regModeOpen},
		{"true is open", "true", regModeOpen},
		{"invite is invite", "invite", regModeInvite},
		{"false is closed", "false", regModeClosed},
		{"unknown value falls back to open", "yes", regModeOpen},
		{"uppercase invite is invite", "INVITE", regModeInvite},
		{"padded false is closed", "  false  ", regModeClosed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := registrationMode(tt.value); got != tt.want {
				t.Errorf("registrationMode(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

// invite/closed mode both reject at the credentials step before any DB access,
// so we can drive them with a nil pool. The settings cache resolves the mode
// from the env-backed config value (GetEffectiveSetting short-circuits on a
// non-empty env value without touching the pool).

func TestRegisterCredentials_InviteMode_RejectsWithoutCode(t *testing.T) {
	h := &AuthHandler{
		Pool:     nil, // must not be touched — rejection happens before any query
		Cfg:      &config.Config{EnableRegistration: "invite"},
		Settings: database.NewSettingsCache(nil),
	}

	body := `{"step":"credentials","email":"test@example.com","password":"longenoughpassword","timezone":"UTC"}`
	r := newRequestWithSession("POST", "/api/auth/register", body)
	w := httptest.NewRecorder()

	h.Register(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if req, _ := resp["requireInviteCode"].(bool); !req {
		t.Errorf("expected requireInviteCode=true in response, got %v", resp)
	}
}

func TestRegisterCredentials_ClosedMode_RejectsRegistration(t *testing.T) {
	h := &AuthHandler{
		Pool:     nil,
		Cfg:      &config.Config{EnableRegistration: "false"},
		Settings: database.NewSettingsCache(nil),
	}

	// Even with an invite code supplied, closed mode must reject entirely.
	body := `{"step":"credentials","email":"test@example.com","password":"longenoughpassword","timezone":"UTC","invite_code":"anything"}`
	r := newRequestWithSession("POST", "/api/auth/register", body)
	w := httptest.NewRecorder()

	h.Register(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if req, _ := resp["requireInviteCode"].(bool); req {
		t.Errorf("closed mode must not offer an invite path, got %v", resp)
	}
}

// The consent gate rejects before any DB access (nil Pool must never be
// touched), so these run without a database.

func TestRegisterCredentials_LegalEnabled_RequiresConsent(t *testing.T) {
	t.Setenv("ENABLE_LEGAL", "true")
	h := &AuthHandler{
		Pool:     nil, // must not be touched — consent rejection happens first
		Cfg:      &config.Config{EnableRegistration: "open"},
		Settings: database.NewSettingsCache(nil),
	}

	// Missing both flags, then each flag alone: all rejected with 400.
	bodies := []string{
		`{"step":"credentials","email":"a@example.com","password":"longenoughpassword"}`,
		`{"step":"credentials","email":"a@example.com","password":"longenoughpassword","legal_accepted":true}`,
		`{"step":"credentials","email":"a@example.com","password":"longenoughpassword","health_consent":true}`,
	}
	for _, body := range bodies {
		r := newRequestWithSession("POST", "/api/auth/register", body)
		w := httptest.NewRecorder()
		h.Register(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %s: status = %d, want %d", body, w.Code, http.StatusBadRequest)
		}
	}
}

func TestRegisterCredentials_LegalEnabled_ConsentPassesToNextGate(t *testing.T) {
	t.Setenv("ENABLE_LEGAL", "true")
	// invite mode: with both consent flags set, the request must clear the
	// consent gate and reach the invite gate (403 requireInviteCode), proving
	// consent does not block a compliant registration.
	h := &AuthHandler{
		Pool:     nil,
		Cfg:      &config.Config{EnableRegistration: "invite"},
		Settings: database.NewSettingsCache(nil),
	}
	body := `{"step":"credentials","email":"a@example.com","password":"longenoughpassword","legal_accepted":true,"health_consent":true}`
	r := newRequestWithSession("POST", "/api/auth/register", body)
	w := httptest.NewRecorder()
	h.Register(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (invite gate)", w.Code, http.StatusForbidden)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if req, _ := resp["requireInviteCode"].(bool); !req {
		t.Errorf("expected requireInviteCode=true after consent gate passed, got %v", resp)
	}
}

func TestRegisterCredentials_LegalDisabled_NoConsentNeeded(t *testing.T) {
	// ENABLE_LEGAL unset: flags are ignored and the flow proceeds to the next
	// gate (invite mode → 403) exactly as before the consent feature.
	h := &AuthHandler{
		Pool:     nil,
		Cfg:      &config.Config{EnableRegistration: "invite"},
		Settings: database.NewSettingsCache(nil),
	}
	body := `{"step":"credentials","email":"a@example.com","password":"longenoughpassword"}`
	r := newRequestWithSession("POST", "/api/auth/register", body)
	w := httptest.NewRecorder()
	h.Register(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (invite gate, no consent gate)", w.Code, http.StatusForbidden)
	}
}

// =============================================================================
// Credential validation (issue #306)
// =============================================================================

// Building blocks for addresses at exact byte lengths. The RFC 5321 maximum
// is 320 bytes: a 64-byte local part, "@", and a 255-byte domain (four
// 63-byte labels joined by three dots).
const (
	emailLocal64   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"          // 64
	emailLabel63   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"           // 63
	emailDomain255 = emailLabel63 + "." + emailLabel63 + "." + emailLabel63 + "." + emailLabel63 // 255
)

func TestValidateEmail(t *testing.T) {
	emailAddr320 := emailLocal64 + "@" + emailDomain255                     // exactly 320 bytes
	emailAddr1000 := emailLocal64 + "@" + strings.Repeat("b", 931) + ".com" // 1000 bytes
	if len(emailAddr320) != MaxEmailBytes {
		t.Fatalf("test fixture emailAddr320 is %d bytes, want %d", len(emailAddr320), MaxEmailBytes)
	}
	if len(emailAddr1000) != 1000 {
		t.Fatalf("test fixture emailAddr1000 is %d bytes, want 1000", len(emailAddr1000))
	}

	tests := []struct {
		name string
		in   string
		want string // "" means: expect rejection
		why  string
	}{
		// The whole point of the issue: before the fix every one of these
		// registered successfully and produced an account whose verification
		// mail could never be sent.
		{"empty", "", "", "no address at all"},
		{"single letter", "a", "", "no @, no domain"},
		{"local part only", "a@", "", "no domain"},
		{"domain only", "@b.com", "", "no local part"},
		{"space in local part", "a b@c.com", "", "unquoted space is not an addr-spec"},
		{"prose", "not an email", "", "the literal example from the issue"},
		{"markup", "<script>", "", "the literal example from the issue"},
		{"two addresses", "a@b.com, c@d.com", "", "a single mailbox is required"},

		// Accepted, with the stored (canonical) form.
		{"plain address", "a@b.com", "a@b.com", ""},
		{"dotless domain accepted", "a@b", "a@b",
			"RFC-valid and deliverable on intranet/self-hosted deployments; validEmail accepts it too"},
		{"uppercase is lowercased", "A@B.COM", "a@b.com",
			"users.email is UNIQUE and compared with =, so the case must be canonical"},
		{"surrounding whitespace is trimmed", "  a@b.com\t", "a@b.com", ""},
		{"mixed case with whitespace", "  Foo.Bar@Example.COM  ", "foo.bar@example.com", ""},
		{"320 bytes is the RFC 5321 maximum", emailAddr320, strings.ToLower(emailAddr320), ""},

		// Length.
		{"321 bytes is one over the cap", emailAddr320 + "x", "", "cap is inclusive at 320"},
		{"1000 bytes", emailAddr1000, "", "oversized key in the users.email UNIQUE btree index"},

		// Header injection. net/mail rejects this on its own today, but the
		// explicit control-character check means that does not have to stay
		// true for us to be safe.
		{"embedded newline", "a@b.com\nBcc: x@y.com", "", "SMTP header injection shape"},
		{"embedded CR", "a@b.com\rBcc: x@y.com", "", "SMTP header injection shape"},
		{"embedded CRLF", "a@b.com\r\nBcc: x@y.com", "", "SMTP header injection shape"},
		{"embedded NUL", "a@b.com\x00", "", "control character"},

		// Decision pinned: the display-name form is REJECTED. net/mail
		// accepts it, but "Foo <a@b.com>" is not a bare mailbox — storing it
		// would let two rows denote the same mailbox while still satisfying
		// the UNIQUE constraint, and it is the shape an injection attempt
		// takes. Same reasoning for a quoted local part, which net/mail
		// un-quotes into an address containing a literal space.
		{"display-name form rejected", "Foo <a@b.com>", "",
			"parses, but is not a bare address"},
		{"bare angle-addr rejected", "<a@b.com>", "",
			"parses, but is not a bare address"},
		{"quoted local part rejected", `"a b"@c.com`, "",
			"net/mail un-quotes this to 'a b@c.com' — a stored address with a space in it"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateEmail(tt.in)
			if tt.want == "" {
				if err == nil {
					t.Fatalf("validateEmail(%q) = %q, want a rejection (%s)", tt.in, got, tt.why)
				}
				if got != "" {
					t.Errorf("validateEmail(%q) returned %q alongside its error; a rejected address must yield no value", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateEmail(%q) = error %v, want %q (%s)", tt.in, err, tt.want, tt.why)
			}
			if got != tt.want {
				t.Errorf("validateEmail(%q) = %q, want %q", tt.in, got, tt.want)
			}
			// The canonical form must be a fixed point: feeding a stored
			// address back in has to yield the identical string, or the
			// email-change flow could produce a duplicate of an existing row.
			again, err := validateEmail(got)
			if err != nil || again != got {
				t.Errorf("validateEmail(%q) = (%q, %v), want (%q, nil) — normalization is not idempotent", got, again, err, got)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
		why     string
	}{
		{"empty", "", true, ""},
		{"nine ascii characters", "123456789", true, "one under the minimum"},
		{"ten ascii characters", "1234567890", false, "exactly the minimum"},
		{"eleven ascii characters", "12345678901", false, ""},

		// Decision pinned: the minimum counts RUNES, not bytes. The message
		// says "10 characters", so it must mean characters. Under the old
		// len() check this 4-character passphrase (12 bytes) was accepted
		// while a 9-character ASCII one was not.
		{"four-rune CJK passphrase rejected", "電気自動", true,
			"the case from the issue: 4 runes / 12 bytes — passed the old byte check"},
		{"five-rune CJK passphrase rejected", "電気自動車", true, "5 runes / 15 bytes"},
		{"ten-rune CJK passphrase accepted", "電気自動車電気自動車", false,
			"10 runes / 30 bytes"},
		{"nine-rune CJK passphrase rejected", "電気自動車電気自動", true, "9 runes"},
		{"ten combining-heavy runes accepted", "ééééééééét", false, "10 runes, 19 bytes"},

		// Whitespace-only is rejected rather than trimmed: trimming would
		// silently change the secret the user typed.
		{"ten spaces", "          ", true, "whitespace-only"},
		{"mixed whitespace", " \t\n\r \t\n\r \t", true, "whitespace-only"},
		{"padded real password accepted", "  hunter2hunter2  ", false,
			"interior content, so it is a real password; must NOT be trimmed away"},

		// Upper bound: argon2id has no intrinsic length limit, so an
		// unbounded password lets a client make the server Blake2b-hash
		// megabytes on every write.
		{"exactly the byte cap", strings.Repeat("x", MaxPasswordBytes), false, ""},
		{"one byte over the cap", strings.Repeat("x", MaxPasswordBytes+1), true, ""},
		{"five megabytes", strings.Repeat("x", 5<<20), true, "the CPU-burn vector from the issue"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.in)
			if tt.wantErr && err == nil {
				t.Fatalf("validatePassword(len=%d) = nil, want an error (%s)", len(tt.in), tt.why)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validatePassword(len=%d) = %v, want nil (%s)", len(tt.in), err, tt.why)
			}
		})
	}
}

// The password minimum must stay expressible to users as "10 characters" —
// the client placeholder says so and the server message says so.
func TestValidatePasswordMessageMatchesPolicy(t *testing.T) {
	err := validatePassword("123456789")
	if err == nil {
		t.Fatal("a 9-character password must be rejected")
	}
	if !strings.Contains(err.Error(), "10 characters") {
		t.Errorf("error = %q, want it to state the 10-character minimum", err)
	}
}

// =============================================================================
// The validator at each entry point
// =============================================================================

// Every one of these registers successfully before the fix. A nil Pool proves
// the rejection happens before any database access — and, for the oversized
// password, before argon2id is handed megabytes.
func TestRegisterCredentials_RejectsInvalidEmail(t *testing.T) {
	bad := []string{
		"a",
		"not an email",
		"<script>",
		"a@",
		"@b.com",
		"a b@c.com",
		"Foo <a@b.com>",
		"a@b.com\nBcc: x@y.com", // real newline; json.Marshal encodes it, the server decodes it back
		emailLocal64 + "@" + strings.Repeat("b", 931) + ".com",
		strings.Repeat("x", 5<<20) + "@example.com",
	}
	for _, email := range bad {
		h := &AuthHandler{
			Pool:     nil, // must not be touched
			Cfg:      &config.Config{EnableRegistration: "open"},
			Settings: database.NewSettingsCache(nil),
		}
		body, _ := json.Marshal(map[string]any{
			"step": "credentials", "email": email,
			"password": "longenoughpassword", "timezone": "UTC",
		})
		r := newRequestWithSession("POST", "/api/auth/register", string(body))
		w := httptest.NewRecorder()
		h.Register(w, r)

		label := email
		if len(label) > 40 {
			label = label[:40] + "…"
		}
		if w.Code != http.StatusBadRequest {
			t.Errorf("email %q: status = %d, want %d", label, w.Code, http.StatusBadRequest)
		}
	}
}

func TestRegisterCredentials_RejectsOversizedPassword(t *testing.T) {
	h := &AuthHandler{
		Pool:     nil, // argon2id must never see this
		Cfg:      &config.Config{EnableRegistration: "open"},
		Settings: database.NewSettingsCache(nil),
	}
	body, _ := json.Marshal(map[string]any{
		"step": "credentials", "email": "a@b.com",
		"password": strings.Repeat("x", 5<<20), "timezone": "UTC",
	})
	r := newRequestWithSession("POST", "/api/auth/register", string(body))
	w := httptest.NewRecorder()
	h.Register(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestRegisterCredentials_RejectsWhitespaceOnlyPassword(t *testing.T) {
	h := &AuthHandler{
		Pool:     nil,
		Cfg:      &config.Config{EnableRegistration: "open"},
		Settings: database.NewSettingsCache(nil),
	}
	body := `{"step":"credentials","email":"a@b.com","password":"          ","timezone":"UTC"}`
	r := newRequestWithSession("POST", "/api/auth/register", body)
	w := httptest.NewRecorder()
	h.Register(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// A valid address must still clear the email gate and reach the next one
// (invite mode → 403). Without this, "reject everything" would pass the tests
// above.
func TestRegisterCredentials_ValidEmailReachesNextGate(t *testing.T) {
	for _, email := range []string{"a@b.com", "  A.User+tag@Example.COM ", "a@b"} {
		h := &AuthHandler{
			Pool:     nil,
			Cfg:      &config.Config{EnableRegistration: "invite"},
			Settings: database.NewSettingsCache(nil),
		}
		body, _ := json.Marshal(map[string]any{
			"step": "credentials", "email": email,
			"password": "longenoughpassword", "timezone": "UTC",
		})
		r := newRequestWithSession("POST", "/api/auth/register", string(body))
		w := httptest.NewRecorder()
		h.Register(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("email %q: status = %d, want %d (invite gate)", email, w.Code, http.StatusForbidden)
		}
	}
}

// Email CHANGE is the bypass the issue calls out: register with a good
// address, then change it to anything. The old check here was
// `strings.Contains(newEmail, "@")`.
func TestEmailChangeRequest_RejectsInvalidEmail(t *testing.T) {
	bad := []string{
		"a",
		"@b.com",
		"<script>@x",
		"a b@c.com",
		"Foo <a@b.com>",
		emailLocal64 + "@" + strings.Repeat("b", 931) + ".com",
		strings.Repeat("x", 5<<20) + "@example.com",
	}
	for _, email := range bad {
		h := &AuthHandler{Pool: nil} // must not be touched
		body, _ := json.Marshal(map[string]any{"new_email": email})
		r := newRequestWithSession("POST", "/settings/email/request", string(body))
		r = r.WithContext(middleware.WithTestUser(r.Context(), &model.User{ID: 1, Email: "old@example.com"}))
		w := httptest.NewRecorder()
		h.EmailChangeRequest(w, r)

		label := email
		if len(label) > 40 {
			label = label[:40] + "…"
		}
		if w.Code != http.StatusBadRequest {
			t.Errorf("new_email %q: status = %d, want %d", label, w.Code, http.StatusBadRequest)
		}
	}
}

// ...and a valid one must get past the validator to the "same as current"
// check, which is also pre-database. Proves the gate is not a blanket reject
// and that normalization runs (the current address differs only in case).
func TestEmailChangeRequest_NormalizesAndReachesSameEmailCheck(t *testing.T) {
	h := &AuthHandler{Pool: nil}
	body := `{"new_email":"  OLD@Example.COM  "}`
	r := newRequestWithSession("POST", "/settings/email/request", body)
	r = r.WithContext(middleware.WithTestUser(r.Context(), &model.User{ID: 1, Email: "old@example.com"}))
	w := httptest.NewRecorder()
	h.EmailChangeRequest(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if msg, _ := resp["error"].(string); !strings.Contains(msg, "same as your current email") {
		t.Errorf("error = %q, want the same-email message (proves normalization ran and the address was accepted)", msg)
	}
}

// =============================================================================
// The validator gates EVERY write, and gates no read
// =============================================================================

// parseHandlerPackage parses the handler package sources (no test files) so
// the assertions below can look at real call graphs rather than at strings.
func parseHandlerPackage(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the handler package directory: %v", err)
	}
	fset := token.NewFileSet()
	funcs := map[string]*ast.FuncDecl{}
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
			if fd, ok := d.(*ast.FuncDecl); ok {
				funcs[fd.Name.Name] = fd
			}
		}
	}
	if len(funcs) == 0 {
		t.Fatal("no functions parsed from the handler package — the test is not looking at real code")
	}
	return funcs
}

// callsFunc reports whether fn's body contains a call to the named
// package-level function.
func funcCallsIdent(fn *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return true
	})
	return found
}

// TestCredentialValidatorsGateEveryWrite is the structural half of issue #306:
// "a validator that only guards one of the three is not a validator". A new
// user-creating or email-changing path that forgets the gate fails here even
// if it has no test of its own.
func TestCredentialValidatorsGateEveryWrite(t *testing.T) {
	funcs := parseHandlerPackage(t)

	emailWrites := []string{
		"registerCredentials", // credential registration (auth.go)
		"handleLogin",         // OIDC auto-provisioning (oidc.go)
		"EmailChangeRequest",  // email change (auth_email.go)
	}
	for _, name := range emailWrites {
		fn, ok := funcs[name]
		if !ok {
			t.Errorf("%s not found — was it renamed? The email validator must follow it", name)
			continue
		}
		if !funcCallsIdent(fn, "validateEmail") {
			t.Errorf("%s does not call validateEmail; every path that writes users.email must go through it", name)
		}
	}

	passwordWrites := []string{
		"registerCredentials", // auth.go
		"ResetPassword",       // auth_password.go
		"Password",            // settings.go (SettingsHandler.Password)
	}
	for _, name := range passwordWrites {
		fn, ok := funcs[name]
		if !ok {
			t.Errorf("%s not found — was it renamed? The password validator must follow it", name)
			continue
		}
		if !funcCallsIdent(fn, "validatePassword") {
			t.Errorf("%s does not call validatePassword; every path that writes a password hash must go through it", name)
		}
	}
}

// TestCredentialValidatorsDoNotGateLogin pins the other half: the validators
// gate writes, NOT reads. Accounts created before #306 may hold an address
// that validateEmail now rejects, and a password that validatePassword now
// rejects. They must keep being able to log in.
func TestCredentialValidatorsDoNotGateLogin(t *testing.T) {
	funcs := parseHandlerPackage(t)

	readPaths := []string{
		"Login",          // auth.go — password login
		"ForgotPassword", // auth_password.go — reset request, looks the user up by email
		"VerifyEmail",    // auth_email.go — consumes a token for an existing address
		"verifyPassword", // auth_helpers.go — the hash comparison itself
	}
	for _, name := range readPaths {
		fn, ok := funcs[name]
		if !ok {
			t.Errorf("%s not found — was it renamed?", name)
			continue
		}
		if funcCallsIdent(fn, "validateEmail") {
			t.Errorf("%s calls validateEmail; that would lock out every account whose address predates the validator", name)
		}
		if funcCallsIdent(fn, "validatePassword") {
			t.Errorf("%s calls validatePassword; that would lock out every account whose password predates the validator", name)
		}
	}
}

// In the OIDC handler the gate must sit in the auto-CREATE branch, below the
// FindOIDCAccount / auto-link lookups. Validating before them would turn a
// grandfathered address into a failed login instead of a successful one.
func TestOIDCEmailValidationRunsAfterTheLookups(t *testing.T) {
	funcs := parseHandlerPackage(t)
	fn, ok := funcs["handleLogin"]
	if !ok {
		t.Fatal("handleLogin not found")
	}

	var lookupPos, validatePos token.Pos
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.SelectorExpr:
			if f.Sel.Name == "FindOIDCAccount" && lookupPos == token.NoPos {
				lookupPos = call.Pos()
			}
		case *ast.Ident:
			if f.Name == "validateEmail" && validatePos == token.NoPos {
				validatePos = call.Pos()
			}
		}
		return true
	})

	if lookupPos == token.NoPos {
		t.Fatal("FindOIDCAccount call not found in handleLogin")
	}
	if validatePos == token.NoPos {
		t.Fatal("validateEmail call not found in handleLogin")
	}
	if validatePos < lookupPos {
		t.Error("validateEmail runs before the OIDC account lookup; it must gate only the auto-create branch, or existing accounts with grandfathered addresses can no longer sign in")
	}
}
