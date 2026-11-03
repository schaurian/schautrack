package e2eguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSuiteNeverDiscoversContainersByListing forbids `docker ps` in the
// Playwright tree.
//
// The suite used to find its database with `docker ps | grep schautrack.*db`
// and take whatever matched — a dev stack, or another checkout's test stack —
// and setup-test-user.ts then rewrote and wiped that database's users. With
// several checkouts running stacks side by side that is how one run destroyed
// another's data. Containers are named in e2e/fixtures/containers.ts from the
// compose project instead; nothing may go back to guessing.
func TestSuiteNeverDiscoversContainersByListing(t *testing.T) {
	scanned := 0
	err := filepath.WalkDir(e2eDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".ts") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		for i, line := range strings.Split(stripComments(string(src)), "\n") {
			if strings.Contains(line, "docker ps") || strings.Contains(line, "'ps'") {
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
		t.Fatalf("no .ts files found under %s; the guard would pass vacuously", e2eDir)
	}
}
