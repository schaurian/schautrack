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
