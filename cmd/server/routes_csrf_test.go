package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// csrfExempt are the only state-changing session-surface routes allowed to
// skip session.CsrfProtection. Both are pre-authentication passkey steps: the
// WebAuthn assertion they verify is bound to this origin by the browser, which
// a cross-site form cannot produce.
var csrfExempt = map[string]bool{
	"/passkeys/login/begin":  true,
	"/passkeys/login/finish": true,
}

var mutatingRoute = regexp.MustCompile(`\.(Post|Put|Patch|Delete)\("([^"]+)"`)

// TestSessionMutatingRoutesRequireCSRF fails when a POST/PUT/PATCH/DELETE route
// registered in main.go lacks session.CsrfProtection.
//
// The router is assembled inside main(), so this reads the source rather than
// the live route table. /api/ai/estimate was once registered without it — it
// spends the operator's AI budget, so it is exactly the kind of request a
// forged cross-site POST should not be able to trigger. (/api/v1 is a separate
// sub-router that accepts bearer tokens only and is mounted, not matched here.)
func TestSessionMutatingRoutesRequireCSRF(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for i, line := range strings.Split(string(src), "\n") {
		m := mutatingRoute.FindStringSubmatch(line)
		if m == nil || strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		checked++
		if csrfExempt[m[2]] {
			continue
		}
		if !strings.Contains(line, "session.CsrfProtection") {
			t.Errorf("main.go:%d: %s %s is registered without session.CsrfProtection", i+1, strings.ToUpper(m[1]), m[2])
		}
	}
	// Guard the guard: if route registration moves or changes shape, this
	// must not pass vacuously.
	if checked < 50 {
		t.Fatalf("only %d mutating routes found in main.go; the scan no longer matches how routes are registered", checked)
	}
}
