package e2eguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSuiteNeverDiscoversContainersByListing forbids `docker ps` in the
// Playwright tree and in scripts/.
//
// The suite used to find its database with `docker ps | grep schautrack.*db`
// and take whatever matched — a dev stack, or another checkout's test stack —
// and setup-test-user.ts then rewrote and wiped that database's users. With
// several checkouts running stacks side by side that is how one run destroyed
// another's data. Containers are named in e2e/fixtures/containers.ts from the
// compose project instead; nothing may go back to guessing.
func TestSuiteNeverDiscoversContainersByListing(t *testing.T) {
	// scripts/ too: demo-seed.ts deletes rows in whatever database it reaches,
	// and the same `docker ps | grep` guess outlived the e2e fix there.
	for _, dir := range []string{e2eDir, filepath.Join("..", "..", "scripts")} {
		scanned := 0
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || (!strings.HasSuffix(path, ".ts") && !strings.HasSuffix(path, ".sh")) {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			text := string(src)
			if strings.HasSuffix(path, ".ts") {
				text = stripComments(text)
			}
			for i, line := range strings.Split(text, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue // shell comment
				}
				if listsContainers(line) {
					t.Errorf("%s:%d lists running containers to pick one; name it via e2e/fixtures/containers.ts instead:\n\t%s",
						path, i+1, strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if scanned == 0 {
			t.Fatalf("no .ts/.sh files found under %s; the guard would pass vacuously", dir)
		}
	}
}

// listsContainers reports whether a line enumerates running containers: the
// shell forms (`docker ps`, `docker container ls`/`list`) or an argv-style
// "ps" / 'ps' handed to execFileSync and friends.
func listsContainers(line string) bool {
	for _, needle := range []string{"docker ps", "docker container ls", "docker container list", `'ps'`, `"ps"`} {
		if strings.Contains(line, needle) {
			return true
		}
	}
	return false
}

// TestListsContainersCatchesEveryForm keeps the matcher honest on its own,
// since the tree it scans is (correctly) clean.
func TestListsContainersCatchesEveryForm(t *testing.T) {
	for _, line := range []string{
		`execSync('docker ps --format "{{.Names}}"')`,
		`execFileSync('docker', ['ps', '--format', '{{.Names}}'])`,
		`execFileSync("docker", ["ps", "-q"])`,
		`docker container ls --filter name=db`,
		`docker container list -q`,
	} {
		if !listsContainers(line) {
			t.Errorf("not caught: %s", line)
		}
	}
	for _, line := range []string{
		`execFileSync('docker', ['exec', '-i', DB_CONTAINER, 'psql'])`,
		`docker inspect schautrack-test-web-1`,
	} {
		if listsContainers(line) {
			t.Errorf("false positive: %s", line)
		}
	}
}
