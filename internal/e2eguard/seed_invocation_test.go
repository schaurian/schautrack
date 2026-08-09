// Package e2eguard holds no production code. It exists to host a build-time
// assertion about the Playwright suite that Go's test runner can enforce, so it
// rides the existing `go test ./...` CI job instead of needing a JS lint
// toolchain this repo does not otherwise have. internal/ui does the same thing
// for the TypeScript client and internal/config/readme_env_test.go for the
// README's environment-variable table.
package e2eguard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// e2eDir is the tree this assertion reads, relative to this package.
var e2eDir = filepath.Join("..", "..", "e2e")

// seedOwner is the one file allowed to invoke the seed: the spec behind the
// `setup` project, which every other project depends on directly or
// transitively.
const seedOwner = "global-setup.ts"

// seedScript is the destructive script. setup-test-user.ts rewrites the password
// hash, `email_verified`, `totp_enabled` and `totp_secret` of every shared test
// user, drops their backup codes, wipes the main user's entries / weights /
// todos / notes, deletes the links between them and resets two admin settings.
const seedScript = "setup-test-user"

// blockComment and lineComment strip commentary before scanning. Both are
// needed for correctness, not tidiness: fixtures/helpers.ts explains in a line
// comment why bcryptHash lives where it does "so setup-test-user.ts can use
// it", and onboarding.spec.ts names the script in a JSDoc block. A scan that
// skipped this step would fail on prose.
//
// lineComment refuses to match a "//" preceded by a colon so that a URL inside
// a string ("https://...") does not swallow the rest of its line. The residual
// risk is a bare "//" inside a string literal, which would truncate that line
// early — a false negative (a missed violation), never a false positive (a
// wrongly failed build). That asymmetry is the right one here.
var (
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineComment  = regexp.MustCompile(`(^|[^:])//[^\n]*`)
)

// stripComments blanks commentary so only executable code is scanned. Comments
// are replaced by the newlines they spanned rather than deleted, so line
// numbers after a multi-line comment still map to the original file.
func stripComments(src string) string {
	src = blockComment.ReplaceAllStringFunc(src, func(m string) string {
		return strings.Repeat("\n", strings.Count(m, "\n"))
	})
	// The leading capture is the character before "//"; it is part of the match
	// and has to survive. Line comments cannot span newlines, so none are lost.
	return lineComment.ReplaceAllStringFunc(src, func(m string) string {
		if len(m) > 0 && m[0] != '/' {
			return m[:1]
		}
		return ""
	})
}

// TestSeedIsInvokedOnlyFromGlobalSetup pins the ordering invariant that #461
// broke.
//
// Playwright's only cross-project ordering primitive is `dependencies`, and it
// orders a project against its ancestors — never against its siblings. Every
// project bar `setup` and `shutdown` is a sibling of some other project, so a
// destructive global write placed in any of them runs CONCURRENTLY with specs
// that own the rows it rewrites. The seed used to be invoked from
// admin-setup.ts, whose only dependency is `setup` — exactly like `2fa`,
// `auth`, `stepup`, `passkey` and `chromium`. A re-seed landing between the two
// halves of two-factor.spec's serial group reset `totp_enabled` to false, so
// the login took the non-2FA branch and `getByLabel('2FA Code')` matched
// nothing at all for its whole 10s budget.
//
// Nothing about that is specific to 2FA: the same window could delete an entry,
// a todo, a note or an account link out from under the project that had just
// written it. So the rule is positional rather than per-symptom — the seed runs
// in `setup`, which everything else waits on, or it races something.
func TestSeedIsInvokedOnlyFromGlobalSetup(t *testing.T) {
	var offenders []string
	scanned := 0
	ownerFound := false

	err := filepath.WalkDir(e2eDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".ts") {
			return nil
		}
		base := filepath.Base(path)
		// The script may of course name itself.
		if base == seedScript+".ts" {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		if !strings.Contains(stripComments(string(src)), seedScript) {
			return nil
		}
		if base == seedOwner {
			ownerFound = true
			return nil
		}
		rel, relErr := filepath.Rel(e2eDir, path)
		if relErr != nil {
			rel = path
		}
		offenders = append(offenders, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", e2eDir, err)
	}

	// A scan that found nothing proves nothing. Guard against the whole test
	// silently passing because the tree moved or the walk matched no files.
	if scanned == 0 {
		t.Fatalf("scanned no .ts files under %s — the guard is not looking at the suite", e2eDir)
	}
	if !ownerFound {
		t.Errorf("%s no longer invokes %s.ts: the destructive seed has to run in the `setup` project, "+
			"which every other project depends on. If it moved, move this guard with it.", seedOwner, seedScript)
	}
	for _, f := range offenders {
		t.Errorf("e2e/%s invokes %s.ts. That seed is destructive and suite-wide, and Playwright's "+
			"`dependencies` orders a project against its ancestors but never against its siblings, so "+
			"running it anywhere except the `setup` project races the specs that own the rows it "+
			"rewrites (#461). Invoke it from e2e/%s only.", f, seedScript, seedOwner)
	}
}
