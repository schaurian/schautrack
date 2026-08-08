package handler

import (
	"strings"
	"testing"
	"time"

	"schautrack/internal/database"
	"schautrack/internal/session"
)

// The admin-settings validators are the last line of defence in front of
// restart-tier configuration. A value that passes validation and then fails to
// parse at boot does not produce a 400 — it produces a container that will not
// come up, or one that comes up with a silently different setting. These tables
// pin exactly what each validator accepts, including the surprising cases that
// come from the stdlib parsers underneath.

// validatorCase is one (input, accepted?) pair.
type validatorCase struct {
	in   string
	ok   bool
	note string // why this case matters, when it isn't obvious
}

func runValidatorCases(t *testing.T, name string, fn func(string) error, cases []validatorCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(name+"/"+quoteForName(tc.in), func(t *testing.T) {
			err := fn(tc.in)
			if tc.ok && err != nil {
				t.Fatalf("%s(%q) = %v, want nil (%s)", name, tc.in, err, tc.note)
			}
			if !tc.ok && err == nil {
				t.Fatalf("%s(%q) = nil, want error (%s)", name, tc.in, tc.note)
			}
		})
	}
}

// quoteForName makes a subtest name out of an arbitrary input value; the empty
// string and whitespace-bearing values would otherwise produce unreadable or
// colliding names.
func quoteForName(v string) string {
	if v == "" {
		return "empty"
	}
	r := strings.NewReplacer(" ", "_", "/", "%2F", "\r", "\\r", "\n", "\\n")
	return r.Replace(v)
}

func TestValidBool(t *testing.T) {
	runValidatorCases(t, "validBool", validBool, []validatorCase{
		{in: "", ok: true, note: "empty is the unset case"},
		{in: "true", ok: true},
		{in: "false", ok: true},
		// Comparison is exact — the settings are compared to the literal
		// "true" string at read time (see legalPagesEnabled), so anything
		// else would read as false.
		{in: "True", ok: false, note: "exact match only"},
		{in: "TRUE", ok: false, note: "exact match only"},
		{in: "1", ok: false},
		{in: "0", ok: false},
		{in: "yes", ok: false},
		{in: "on", ok: false},
		{in: " true", ok: false, note: "not trimmed"},
		{in: "true ", ok: false, note: "not trimmed"},
	})
}

func TestValidURL(t *testing.T) {
	runValidatorCases(t, "validURL", validURL, []validatorCase{
		{in: "", ok: true, note: "empty is the unset case (base_url auto-detects)"},
		{in: "https://example.com", ok: true},
		{in: "http://example.com", ok: true},
		{in: "https://example.com:8443/p?q=1", ok: true},
		{in: "https://[::1]:8080", ok: true, note: "IPv6 literal host"},
		// url.Parse lowercases the scheme, so the allow-list is
		// case-insensitive without any extra work here.
		{in: "HTTPS://example.com", ok: true, note: "url.Parse lowercases the scheme"},

		{in: "example.com", ok: false, note: "no scheme, no host"},
		{in: "//example.com", ok: false, note: "scheme-relative: no scheme"},
		{in: "https://", ok: false, note: "no host"},
		{in: "http://exa mple.com", ok: false, note: "url.Parse rejects the space"},
		{in: "https://example.com/\nx", ok: false, note: "control character"},

		// Scheme allow-list (added with #309). base_url is interpolated into
		// SEO meta tags and used to build the OIDC redirect URL; url.Parse on
		// its own is happy with any scheme that has a host.
		{in: "javascript://x", ok: false, note: "scheme allow-list: not http(s)"},
		{in: "javascript:alert(1)", ok: false, note: "no host, and not http(s)"},
		{in: "ftp://x", ok: false, note: "scheme allow-list: not http(s)"},
		{in: "data:text/html,x", ok: false, note: "no host, and not http(s)"},
		{in: "file:///etc/passwd", ok: false, note: "scheme allow-list: not http(s)"},
	})
}

func TestValidEmail(t *testing.T) {
	runValidatorCases(t, "validEmail", validEmail, []validatorCase{
		{in: "", ok: true, note: "empty is the unset case (smtp_from falls back to support_email)"},
		{in: "a@b.com", ok: true},
		{in: "florian@schauer.to", ok: true},
		{in: "a+tag@b.com", ok: true},
		{in: "A@B.COM", ok: true, note: "case is preserved, not normalised"},
		// mail.ParseAddress accepts a bare domain and an address literal, and
		// both round-trip unchanged, so they pass the bare-address check too.
		{in: "a@b", ok: true, note: "RFC-valid single-label domain"},
		{in: "a@[192.168.0.1]", ok: true, note: "RFC-valid address literal"},

		// Bare-address requirement (added with #309). smtp_from goes verbatim
		// into both the From: header and the SMTP MAIL FROM argument
		// (service.EmailService.send → c.Mail(from)); the display-name form is
		// legal in the header but not in the envelope, so accepting it here
		// means every send fails after the restart.
		{in: "Foo <a@b.com>", ok: false, note: "display-name form"},
		{in: `"Foo" <a@b.com>`, ok: false, note: "quoted display-name form"},
		{in: "<a@b.com>", ok: false, note: "angle-addr form"},
		{in: " a@b.com", ok: false, note: "ParseAddress trims, so the value would not round-trip"},
		{in: "a@b.com ", ok: false, note: "ParseAddress trims, so the value would not round-trip"},

		{in: "notanemail", ok: false},
		{in: "a@", ok: false},
		{in: "@b.com", ok: false},
		{in: "a@b.com, c@d.com", ok: false, note: "single address only"},
		{in: "a@b.com\r\nBcc: x@y.com", ok: false, note: "header injection"},
	})
}

func TestValidNonNegInt(t *testing.T) {
	runValidatorCases(t, "validNonNegInt", validNonNegInt, []validatorCase{
		{in: "", ok: true, note: "empty is the unset case"},
		{in: "0", ok: true, note: "0 = unlimited for ai_daily_limit"},
		{in: "1", ok: true},
		{in: "100", ok: true},
		{in: "007", ok: true, note: "Atoi accepts leading zeros"},
		{in: "+1", ok: true, note: "Atoi accepts a leading plus"},

		{in: "-1", ok: false},
		{in: "abc", ok: false},
		{in: "1.5", ok: false},
		{in: " 1", ok: false, note: "Atoi does not trim"},
		{in: "1 ", ok: false, note: "Atoi does not trim"},
		{in: "99999999999999999999", ok: false, note: "Atoi range error"},
	})
}

func TestValidPositiveInt(t *testing.T) {
	runValidatorCases(t, "validPositiveInt", validPositiveInt, []validatorCase{
		{in: "", ok: true, note: "empty is the unset case (rate_limit_auth defaults to 10)"},
		{in: "1", ok: true, note: "lower boundary"},
		{in: "10", ok: true},
		{in: "99999", ok: true},

		{in: "0", ok: false, note: "zero would disable the auth rate limit entirely"},
		{in: "-1", ok: false},
		{in: "abc", ok: false},
		{in: "1.5", ok: false},
		{in: "99999999999999999999", ok: false, note: "Atoi range error"},
	})
}

func TestValidPort(t *testing.T) {
	runValidatorCases(t, "validPort", validPort, []validatorCase{
		{in: "", ok: true, note: "empty is the unset case (smtp_port defaults to 587)"},
		{in: "1", ok: true, note: "lower boundary"},
		{in: "587", ok: true},
		{in: "65535", ok: true, note: "upper boundary"},

		{in: "0", ok: false, note: "below the lower boundary"},
		{in: "65536", ok: false, note: "above the upper boundary"},
		{in: "-1", ok: false},
		{in: "80 ", ok: false, note: "Atoi does not trim, so a stray space is rejected"},
		{in: "0x50", ok: false, note: "Atoi is base 10 only"},
		{in: "smtp", ok: false},
	})
}

func TestValidDuration(t *testing.T) {
	runValidatorCases(t, "validDuration", validDuration, []validatorCase{
		{in: "", ok: true, note: "empty is the unset case (step_up_ttl defaults to 30m)"},
		{in: "30m", ok: true},
		{in: "1h30m", ok: true},
		{in: "1h30m45s", ok: true},
		{in: "1ms", ok: true, note: "no lower bound beyond > 0"},
		{in: "+5m", ok: true, note: "ParseDuration accepts a leading plus"},

		{in: "0", ok: false, note: "parses, but <= 0"},
		{in: "0s", ok: false, note: "parses, but <= 0"},
		{in: "-5m", ok: false, note: "parses, but <= 0"},
		{in: "5", ok: false, note: "missing unit"},
		{in: "9999999h", ok: false, note: "overflows int64 nanoseconds"},
		{in: "30M", ok: false, note: "units are case-sensitive; M is not minutes"},
		{in: "  30m", ok: false, note: "ParseDuration does not trim"},
		{in: "forever", ok: false},
	})
}

func TestValidRPID(t *testing.T) {
	runValidatorCases(t, "validRPID", validRPID, []validatorCase{
		{in: "", ok: true, note: "empty is the unset case (RP ID derived from the request host)"},
		{in: "example.com", ok: true},
		{in: "sub.example.com", ok: true},
		{in: "localhost", ok: true, note: "the local-dev RP ID"},
		{in: "EXAMPLE.COM", ok: true, note: "case is not normalised here"},

		{in: "https://example.com", ok: false, note: "scheme"},
		{in: "example.com:443", ok: false, note: "port"},
		{in: "example.com/path", ok: false, note: "path"},
		{in: "::1", ok: false, note: "IPv6 literal — rejected because it contains ':'"},
		{in: "[::1]", ok: false, note: "bracketed IPv6 literal — also contains ':'"},
		{in: "//example.com", ok: false, note: "contains '/'"},

		// Known gap: the validator is a three-character blocklist, so anything
		// without :// , / or : passes — including values that are not valid
		// hostnames at all. Getting the RP ID wrong breaks passkey login for
		// every user at once, with no error at write time. Pinned here so the
		// gap is visible; tracked separately rather than widened under #309.
		{in: "example.com ", ok: true, note: "KNOWN GAP: trailing whitespace accepted"},
		{in: "not a hostname", ok: true, note: "KNOWN GAP: spaces accepted"},
		{in: "exam_ple.com", ok: true, note: "KNOWN GAP: underscore accepted"},
	})
}

func TestOneOf(t *testing.T) {
	// ai_provider's allow-list, used as the representative instance.
	fn := oneOf("openai", "claude", "ollama", "")
	runValidatorCases(t, "oneOf", fn, []validatorCase{
		{in: "", ok: true, note: "empty is in the allow-list explicitly"},
		{in: "openai", ok: true},
		{in: "claude", ok: true},
		{in: "ollama", ok: true},

		{in: "OpenAI", ok: false, note: "exact comparison, no case folding"},
		{in: "OPENAI", ok: false, note: "exact comparison, no case folding"},
		{in: " openai", ok: false, note: "exact comparison, no trimming"},
		{in: "openai ", ok: false, note: "exact comparison, no trimming"},
		{in: "gemini", ok: false},
	})

	// The error message must list the allowed values — it is surfaced verbatim
	// to the admin as the 400 body (see AdminHandler.UpdateSettings).
	err := fn("gemini")
	if err == nil {
		t.Fatal("oneOf(...)(\"gemini\") = nil, want error")
	}
	for _, want := range []string{"openai", "claude", "ollama"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("oneOf error %q does not mention allowed value %q", err.Error(), want)
		}
	}

	// An empty allow-list rejects everything, including the empty string —
	// worth knowing before anyone writes oneOf() with no arguments.
	if oneOf()("") == nil {
		t.Error("oneOf()(\"\") = nil, want error: an empty allow-list allows nothing")
	}
}

// knownTiers / knownSections are the drift guard for a table that is edited by
// hand every time a setting is added.
//
// knownSections must stay in sync with SECTION_ORDER in
// client/src/pages/Admin/Admin.tsx — the Admin page iterates that constant, so
// a setting in a section the client does not know about is silently never
// rendered.
var (
	knownTiers = map[string]bool{
		"hot":     true, // takes effect on the next request
		"restart": true, // needs a server restart
	}
	knownSections = map[string]bool{
		"general":  true,
		"ai":       true,
		"oidc":     true,
		"passkeys": true,
		"features": true,
		"smtp":     true,
		"security": true,
		"legal":    true,
		"seo":      true,
	}
)

func TestAdminSettingsTableIsConsistent(t *testing.T) {
	if len(adminSettings) == 0 {
		t.Fatal("adminSettings is empty")
	}

	seenKey := map[string]int{}
	seenEnv := map[string]int{}
	usedSections := map[string]bool{}

	for i := range adminSettings {
		s := &adminSettings[i]

		if s.Key == "" {
			t.Errorf("adminSettings[%d]: empty Key", i)
			continue
		}
		if prev, dup := seenKey[s.Key]; dup {
			// A duplicate key silently shadows the earlier entry in
			// adminSettingByKey, so one of the two settings becomes
			// unreachable from the write path.
			t.Errorf("duplicate Key %q at indexes %d and %d", s.Key, prev, i)
		}
		seenKey[s.Key] = i

		if s.Env == "" {
			t.Errorf("%s: empty Env", s.Key)
		} else {
			if prev, dup := seenEnv[s.Env]; dup {
				// UpdateSettings refuses a write when os.Getenv(spec.Env) is
				// non-empty. Two settings sharing an Env means one env var
				// locks both.
				t.Errorf("duplicate Env %q on %q and %q", s.Env, adminSettings[prev].Key, s.Key)
			}
			seenEnv[s.Env] = i

			// Every entry today is the SCREAMING_SNAKE form of its key, and
			// the whole env-override check depends on the pairing being right.
			if want := strings.ToUpper(s.Key); s.Env != want {
				t.Errorf("%s: Env = %q, want %q (Env must be the upper-cased Key)", s.Key, s.Env, want)
			}
		}

		if !knownTiers[s.Tier] {
			t.Errorf("%s: unknown Tier %q", s.Key, s.Tier)
		}
		if !knownSections[s.Section] {
			t.Errorf("%s: unknown Section %q — add it here and to SECTION_ORDER in client/src/pages/Admin/Admin.tsx", s.Key, s.Section)
		}
		usedSections[s.Section] = true

		if strings.TrimSpace(s.Help) == "" {
			t.Errorf("%s: empty Help (the Admin page renders it under the field)", s.Key)
		}

		// adminSettingByKey must resolve to this exact element — the write
		// path takes the validator and the Secret flag from it.
		got, ok := adminSettingByKey[s.Key]
		if !ok {
			t.Errorf("%s: missing from adminSettingByKey", s.Key)
		} else if got != s {
			t.Errorf("%s: adminSettingByKey points at a different element", s.Key)
		}
	}

	if len(adminSettingByKey) != len(seenKey) {
		t.Errorf("adminSettingByKey has %d entries, adminSettings has %d unique keys", len(adminSettingByKey), len(seenKey))
	}

	// A section listed as known but used by nothing means a dead entry in the
	// client's SECTION_ORDER.
	for section := range knownSections {
		if !usedSections[section] {
			t.Errorf("section %q has no settings — remove it here and from SECTION_ORDER", section)
		}
	}

	// The exact set of credential-bearing settings. Losing a Secret flag here
	// leaks the value to the Admin page *and* writes it into the audit log
	// (see AdminHandler.UpdateSettings), so it must be a deliberate edit.
	wantSecret := map[string]bool{
		"ai_key":                   true,
		"ai_key_encryption_secret": true,
		"oidc_client_secret":       true,
		"smtp_user":                true,
		"smtp_pass":                true,
	}
	// Settings behind the typed-confirmation dialog — each one breaks existing
	// user state when changed (orphans stored AI keys, invalidates passkeys).
	wantDangerous := map[string]bool{
		"ai_key_encryption_secret": true,
		"passkeys_rp_id":           true,
		"passkeys_rp_origins":      true,
	}
	for i := range adminSettings {
		s := &adminSettings[i]
		if s.Secret != wantSecret[s.Key] {
			t.Errorf("%s: Secret = %v, want %v", s.Key, s.Secret, wantSecret[s.Key])
		}
		if s.Dangerous != wantDangerous[s.Key] {
			t.Errorf("%s: Dangerous = %v, want %v", s.Key, s.Dangerous, wantDangerous[s.Key])
		}
	}
	for k := range wantSecret {
		if _, ok := adminSettingByKey[k]; !ok {
			t.Errorf("expected-secret key %q is not in adminSettings", k)
		}
	}
	for k := range wantDangerous {
		if _, ok := adminSettingByKey[k]; !ok {
			t.Errorf("expected-dangerous key %q is not in adminSettings", k)
		}
	}

	// Every Secret entry must actually be redacted by the read path. The
	// stored value never crosses the wire back to the UI; only isSet does.
	const stored = "s3cr3t-value"
	for i := range adminSettings {
		s := &adminSettings[i]
		val := stored
		resp := adminSettingResponse(s, database.SettingResult{Value: &val, Source: "db"})

		if resp["isSet"] != true {
			t.Errorf("%s: isSet = %v, want true when a value is stored", s.Key, resp["isSet"])
		}
		if s.Secret {
			if resp["value"] != "" {
				t.Errorf("%s: Secret setting leaks its value %q through the read path", s.Key, resp["value"])
			}
		} else if resp["value"] != stored {
			t.Errorf("%s: value = %v, want %q", s.Key, resp["value"], stored)
		}
		if resp["secret"] != s.Secret {
			t.Errorf("%s: response secret flag = %v, want %v", s.Key, resp["secret"], s.Secret)
		}
	}

	// An unset setting reports isSet=false and an empty value regardless of
	// the Secret flag.
	for i := range adminSettings {
		s := &adminSettings[i]
		resp := adminSettingResponse(s, database.SettingResult{Value: nil, Source: "none"})
		if resp["isSet"] != false {
			t.Errorf("%s: isSet = %v for an unset value, want false", s.Key, resp["isSet"])
		}
		if resp["value"] != "" {
			t.Errorf("%s: value = %v for an unset value, want empty", s.Key, resp["value"])
		}
	}

	// Secret values must not be echoed even when they come from the
	// environment — the source changes, the redaction rule does not.
	for i := range adminSettings {
		s := &adminSettings[i]
		if !s.Secret {
			continue
		}
		val := stored
		resp := adminSettingResponse(s, database.SettingResult{Value: &val, Source: "env"})
		if resp["value"] != "" {
			t.Errorf("%s: Secret setting leaks its env-sourced value", s.Key)
		}
	}
}

// TestStepUpTTLValidatorAgreesWithParser pins the agreement between the
// validator that gates step_up_ttl at write time and the parser that re-reads
// the same value independently at startup (session.ParseStepUpTTL).
//
// If the two ever disagree, an admin sets a step-up window through the admin
// panel, gets a 200, and the server silently runs with the 30m default.
func TestStepUpTTLValidatorAgreesWithParser(t *testing.T) {
	spec, ok := adminSettingByKey["step_up_ttl"]
	if !ok {
		t.Fatal("step_up_ttl missing from adminSettings")
	}
	if spec.Validate == nil {
		t.Fatal("step_up_ttl has no validator")
	}

	// The fallback, resolved through the parser itself so the test does not
	// hard-code a duplicate of the default.
	fallback := session.ParseStepUpTTL("")

	values := []string{
		"", "1ms", "30s", "5m", "30m", "1h", "1h30m", "1h30m45s", "+5m", "24h",
		"0", "0s", "-5m", "5", "30M", "  30m", "9999999h", "forever", "abc",
	}

	for _, v := range values {
		t.Run(quoteForName(v), func(t *testing.T) {
			accepted := spec.Validate(v) == nil
			got := session.ParseStepUpTTL(v)

			if !accepted {
				// Rejected at write time, so the parser never sees it from the
				// admin panel — but STEP_UP_TTL can still be set as an env var,
				// and then it must fall back rather than do something odd.
				if got != fallback {
					t.Fatalf("ParseStepUpTTL(%q) = %v for a value the validator rejects, want the %v fallback", v, got, fallback)
				}
				return
			}

			if v == "" {
				if got != fallback {
					t.Fatalf("ParseStepUpTTL(\"\") = %v, want the %v fallback", got, fallback)
				}
				return
			}

			want, err := time.ParseDuration(v)
			if err != nil {
				t.Fatalf("validDuration accepted %q but time.ParseDuration rejects it: %v", v, err)
			}
			if got != want {
				t.Fatalf("validDuration accepts %q but ParseStepUpTTL returns %v, want %v — the admin would silently get a different window", v, got, want)
			}
			if want != fallback && got == fallback {
				t.Fatalf("ParseStepUpTTL(%q) silently fell back to %v", v, fallback)
			}
		})
	}
}

// TestRegistrationValidatorAgreesWithMode pins the relationship between the
// oneOf allow-list on enable_registration and registrationMode, which resolves
// the same value at request time.
//
// The two normalise differently: oneOf compares exactly, registrationMode
// lowercases and trims first. That asymmetry is fine as long as everything the
// validator accepts resolves to the mode the admin would expect — this test
// asserts that direction, and pins the rejected-but-understood values so the
// mismatch is a deliberate choice rather than an accident.
func TestRegistrationValidatorAgreesWithMode(t *testing.T) {
	spec, ok := adminSettingByKey["enable_registration"]
	if !ok {
		t.Fatal("enable_registration missing from adminSettings")
	}
	if spec.Validate == nil {
		t.Fatal("enable_registration has no validator")
	}

	// The values the validator is expected to accept, and the mode each one
	// must resolve to. Changing either side without the other is the bug this
	// test exists to catch.
	wantAccepted := map[string]string{
		"":       regModeOpen, // unset → open (fails safe towards usable sign-up)
		"open":   regModeOpen,
		"true":   regModeOpen, // documented synonym for "open"
		"invite": regModeInvite,
		"false":  regModeClosed,
	}

	for v, wantMode := range wantAccepted {
		t.Run("accepted/"+quoteForName(v), func(t *testing.T) {
			if err := spec.Validate(v); err != nil {
				t.Fatalf("validator rejects %q, which the allow-list is supposed to accept: %v", v, err)
			}
			if got := registrationMode(v); got != wantMode {
				t.Fatalf("registrationMode(%q) = %q, want %q", v, got, wantMode)
			}
		})
	}

	// Nothing outside the allow-list may sneak through, and every accepted
	// value must resolve to one of the three canonical modes.
	canonical := map[string]bool{regModeOpen: true, regModeInvite: true, regModeClosed: true}
	candidates := []string{
		"", "open", "true", "false", "invite",
		"Invite", "INVITE", "invite ", " invite", "Open", "True", "False", "FALSE",
		"closed", "disabled", "no", "1", "0", "yes", "off",
	}
	for _, v := range candidates {
		accepted := spec.Validate(v) == nil
		if _, want := wantAccepted[v]; accepted != want {
			t.Errorf("validator accepts %q = %v, want %v", v, accepted, want)
		}
		if accepted && !canonical[registrationMode(v)] {
			t.Errorf("validator accepts %q but registrationMode returns non-canonical %q", v, registrationMode(v))
		}
	}

	// The asymmetry, pinned. registrationMode understands these; the validator
	// does not accept them. That is the safe direction (the admin gets a 400
	// and retypes) but it is an inconsistency, so it should not change silently.
	for _, v := range []string{"Invite", "INVITE", " invite", "invite ", "False", "FALSE", " false "} {
		if spec.Validate(v) == nil {
			t.Errorf("validator now accepts %q — the allow-list changed; confirm registrationMode still agrees", v)
		}
	}
	if got := registrationMode("Invite"); got != regModeInvite {
		t.Errorf("registrationMode(%q) = %q, want %q", "Invite", got, regModeInvite)
	}
	if got := registrationMode(" false "); got != regModeClosed {
		t.Errorf("registrationMode(%q) = %q, want %q", " false ", got, regModeClosed)
	}

	// Anything unrecognised is open registration — the documented fail-safe
	// direction. Only "false" closes sign-up and only "invite" gates it.
	for _, v := range []string{"garbage", "closed", "disabled", "0", "off"} {
		if got := registrationMode(v); got != regModeOpen {
			t.Errorf("registrationMode(%q) = %q, want %q (unrecognised values must fail open)", v, got, regModeOpen)
		}
	}
}
