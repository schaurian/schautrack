package config

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// buildTimeOnly lists environment variables that config reads but a self-hoster
// never sets, so the README's table is not the place for them.
var buildTimeOnly = map[string]string{
	"BUILD_VERSION": "injected by the Docker build via -ldflags; not operator-configurable",
}

// TestReadmeDocumentsEveryEnvVar keeps CLAUDE.md's claim honest: it calls the
// README table "the canonical, exhaustive table with all defaults", and it was
// not — UPDATE_PROVIDER, UPDATE_REPO and UPDATE_BASE_URL configured *where* the
// update check looks and appeared nowhere (#398), so an operator pointing an
// instance at their own fork had to read config.go to find out how.
//
// A doc that is exhaustive-by-assertion stays exhaustive; one that is
// exhaustive-by-intention drifts on the next variable added.
func TestReadmeDocumentsEveryEnvVar(t *testing.T) {
	src, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatalf("reading config.go: %v", err)
	}
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}

	// Both spellings config.go uses to read the environment.
	re := regexp.MustCompile(`(?:os\.Getenv|envOr|envInt|envBool)\("([A-Z][A-Z0-9_]*)"`)
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		seen[m[1]] = true
	}
	if len(seen) == 0 {
		t.Fatal("no environment variables found in config.go — this test is not reading real code")
	}

	var missing []string
	for name := range seen {
		if _, ok := buildTimeOnly[name]; ok {
			continue
		}
		if !strings.Contains(string(readme), "`"+name+"`") {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	for _, name := range missing {
		t.Errorf("%s is read by config.go but absent from README.md; add it to the env table "+
			"(or to buildTimeOnly here, with the reason)", name)
	}
}

// envTableRow matches the first column of a row in one of the README's
// environment-variable tables: "| `SOME_VAR` | ...". Scoping to table rows
// rather than to every backticked token in the section is deliberate — the
// prose around those tables mentions `POST`, `GET` and similar, which match an
// UPPER_SNAKE pattern but are not environment variables.
var envTableRow = regexp.MustCompile("^\\|\\s*`([A-Z][A-Z0-9_]*)`\\s*\\|")

// TestReadmeEnvTableHasNoPhantomVars is the reverse of the test above, and
// exists because that direction alone is only half a guarantee.
//
// TestReadmeDocumentsEveryEnvVar pins code -> docs: every variable config.go
// reads has a README row. Nothing pinned docs -> code, so a row for a variable
// that no longer exists survived indefinitely: deleting an env var from the
// code left its table row behind, still telling operators to set something the
// binary would ignore. That is not hypothetical — it is what happened when
// SESSION_SECRET was removed, and the only reason the table got cleaned up is
// that a human went looking.
//
// The check is deliberately loose about *where* the variable is read: it looks
// for the name as a string literal anywhere under internal/ or cmd/, not just
// in config.go. Several documented variables are read outside the config
// package on purpose — ENABLE_LEGAL in handler/legal.go, STEP_UP_TTL in
// session/store.go, CAPTCHA_BYPASS in service/captcha.go,
// LOGIN_CAPTCHA_GLOBAL_THRESHOLD in handler/login_failures.go — and requiring
// them to live in config.go would be a worse rule than the one it enforces.
//
// What this does NOT catch, to be explicit: a variable that is read and then
// ignored. SESSION_SECRET passed this check for five months, because config.go
// genuinely did read it — the value simply went nowhere. Proving a config value
// reaches behaviour needs dataflow analysis, not a grep; this guard only stops
// the docs from describing a variable that does not exist at all.
func TestReadmeEnvTableHasNoPhantomVars(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("reading README.md: %v", err)
	}

	// Restrict to the "## Environment Variables" section; the rest of the
	// README has tables (the API reference) whose first column is not an env var.
	lines := strings.Split(string(readme), "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "## Environment Variables" {
			start = i
			break
		}
	}
	if start == -1 {
		t.Fatal(`README.md has no "## Environment Variables" heading — this test is not reading the real table`)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "## ") {
			end = i
			break
		}
	}

	var documented []string
	for _, l := range lines[start:end] {
		if m := envTableRow.FindStringSubmatch(l); m != nil {
			documented = append(documented, m[1])
		}
	}
	if len(documented) == 0 {
		t.Fatal("no environment variables found in the README tables — this test is not reading real docs")
	}

	// Collect every quoted string literal under internal/ and cmd/.
	literals := map[string]bool{}
	lit := regexp.MustCompile(`"([A-Z][A-Z0-9_]*)"`)
	for _, root := range []string{filepath.Join("..", "..", "internal"), filepath.Join("..", "..", "cmd")} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range lit.FindAllStringSubmatch(string(src), -1) {
				literals[m[1]] = true
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}
	if len(literals) == 0 {
		t.Fatal("no string literals found under internal/ or cmd/ — this test is not reading real code")
	}

	var phantom []string
	for _, name := range documented {
		if !literals[name] {
			phantom = append(phantom, name)
		}
	}
	sort.Strings(phantom)
	for _, name := range phantom {
		t.Errorf("README.md documents %s in an environment-variable table, but no Go file under "+
			"internal/ or cmd/ mentions it. Either the variable was removed and its row should go "+
			"too, or the name is misspelled — an operator following this table would be setting "+
			"something the binary never reads.", name)
	}
}
