// Package ui holds no production code. It exists to host build-time assertions
// about the TypeScript client that Go's test runner can enforce, so they ride
// the existing `go test ./...` CI job instead of needing a JS lint toolchain
// this repo does not otherwise have. internal/config/readme_env_test.go does
// the same thing for the README's environment-variable table.
package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// clientSrc is the tree these assertions read, relative to this package.
var clientSrc = filepath.Join("..", "..", "client", "src")

// sharedUIDir is exempt: it is where the replacement primitives live, and
// select.tsx has to be allowed to describe the native element it replaces.
var sharedUIDir = filepath.Join("components", "ui")

// blockComment and lineComment strip commentary before scanning for elements.
//
// Both are needed for correctness, not tidiness. MacroSettings.tsx documents
// the control it used to have ("Was a real <select> with opacity:0 ...") inside
// a JSX comment, and select.tsx's doc comment necessarily names the element it
// replaces. A scan that skipped this step would fail on prose.
//
// lineComment deliberately refuses to match a "//" preceded by a colon so that
// a URL in a string ("https://...") does not swallow the rest of its line. The
// residual risk is a bare "//" inside a string literal, which would truncate
// that line early — a false negative (a missed violation), never a false
// positive (a wrongly failed build). That asymmetry is the right one here.
var (
	blockComment = regexp.MustCompile(`(?s)/\*.*?\*/`)
	lineComment  = regexp.MustCompile(`(^|[^:])//[^\n]*`)
)

// nativeSelect matches an opening native <select> tag. The trailing class keeps
// it from firing on a component whose name merely starts with "select"; React
// components are capitalised, so <Select> never collides with this.
var nativeSelect = regexp.MustCompile(`<select[\s/>]`)

// stripComments blanks commentary so only executable JSX is scanned.
//
// Comments are replaced by the newlines they spanned rather than deleted, so
// offsets after a multi-line comment still map to their original line. Deleting
// outright would report violations at the wrong line number.
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

// findNativeSelects returns the 1-based line numbers of native <select> tags in
// src, ignoring any inside comments.
//
// The scan runs over the whole source rather than line by line: an opening tag
// is routinely broken across lines ("<select\n  value={v}>"), and a per-line
// match cannot see the whitespace that follows the tag name.
func findNativeSelects(src string) []int {
	stripped := stripComments(src)
	var lines []int
	for _, loc := range nativeSelect.FindAllStringIndex(stripped, -1) {
		lines = append(lines, strings.Count(stripped[:loc[0]], "\n")+1)
	}
	return lines
}

// TestClientUsesTheSharedSelect enforces CLAUDE.md's "Never use a native
// <select>" rule, which until now was documentation with nothing behind it.
//
// The API token expiry field (#456) sat rendering an unthemed OS dropdown in
// the middle of a themed form until somebody happened to look at it. A native
// <select> opens an OS popup that ignores the dark theme entirely, so the
// failure is invisible to every other test in the suite — it type-checks, it
// renders, it even works. Only a human eye or this test catches it.
func TestClientUsesTheSharedSelect(t *testing.T) {
	type violation struct {
		file string
		line int
	}
	var found []violation
	scanned := 0

	err := filepath.WalkDir(clientSrc, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".tsx" {
			return nil
		}
		rel, relErr := filepath.Rel(clientSrc, path)
		if relErr != nil {
			return relErr
		}
		if strings.HasPrefix(rel, sharedUIDir+string(filepath.Separator)) {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned++
		for _, line := range findNativeSelects(string(src)) {
			found = append(found, violation{file: filepath.ToSlash(filepath.Join("client", "src", rel)), line: line})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", clientSrc, err)
	}

	// Without this the test passes loudly for the wrong reason: a moved client
	// directory or a renamed extension would scan nothing and report success.
	if scanned == 0 {
		t.Fatalf("scanned no .tsx files under %s — this test is not reading real code", clientSrc)
	}

	sort.Slice(found, func(i, j int) bool {
		if found[i].file != found[j].file {
			return found[i].file < found[j].file
		}
		return found[i].line < found[j].line
	})
	for _, v := range found {
		t.Errorf("%s:%d uses a native <select>; use the Radix Select in "+
			"client/src/components/ui/select.tsx instead (see CLAUDE.md). A native "+
			"<select> renders an OS popup that ignores the dark theme.", v.file, v.line)
	}
}

// TestNativeSelectDetection pins the matcher's behaviour with inline fixtures.
//
// This is the safeguard that keeps the guard above meaningful. There is no
// longer a single real native <select> anywhere in the client, so the guard
// passes on an empty result set and would go on passing if the matcher silently
// broke. These cases fail instead.
func TestNativeSelectDetection(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"plain element", "<select value={v}>", true},
		{"self closing", "<select/>", true},
		{"newline after tag", "<select\n  value={v}>", true},
		{"radix component", "<Select value={v}>", false},
		{"jsx block comment", "{/* Was a real <select> with opacity:0 */}", false},
		{"doc comment", "/**\n * a button instead of a native <select>, so this\n */", false},
		{"line comment", "// TODO: replace the <select> here", false},
		{"url on the line survives", `const u = "https://x.dev"; <select>`, true},
		{"prefixed identifier", "<selectable />", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := len(findNativeSelects(tc.src)) > 0
			if got != tc.want {
				t.Errorf("findNativeSelects(%q) found=%v, want %v\nafter stripping comments: %q",
					tc.src, got, tc.want, stripComments(tc.src))
			}
		})
	}
}

// TestReportedLineSurvivesComments pins the line numbers the guard reports.
//
// Blanking a comment instead of deleting it is what keeps these honest; an
// earlier draft deleted comments outright and pointed at the wrong line in any
// file with a licence header or a multi-line doc comment above the offence.
func TestReportedLineSurvivesComments(t *testing.T) {
	src := "import x from 'y'\n/**\n * a doc comment\n * spanning lines\n */\nconst A = () => <select />\n"
	got := findNativeSelects(src)
	want := []int{6}
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("findNativeSelects reported lines %v, want %v", got, want)
	}
}

// TestClientSrcIsWhereWeThinkItIs fails with a clear message if the tree moves,
// rather than letting the guard above degrade into a no-op.
func TestClientSrcIsWhereWeThinkItIs(t *testing.T) {
	info, err := os.Stat(filepath.Join(clientSrc, sharedUIDir, "select.tsx"))
	if err != nil {
		t.Fatalf("the shared Select primitive is missing from %s: %v\n%s",
			filepath.Join(clientSrc, sharedUIDir), err,
			fmt.Sprintf("if the client moved, update clientSrc in %s", "internal/ui/client_controls_test.go"))
	}
	if info.IsDir() {
		t.Fatal("select.tsx is a directory")
	}
}
