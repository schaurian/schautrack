// Command apidocs regenerates the committed API artifacts from
// internal/openapi.
//
//	go run ./cmd/apidocs          # write the files
//	go run ./cmd/apidocs -check   # fail if they are stale (used by CI)
//
// Two files are produced:
//
//	api/openapi.json  the machine-readable contract, for client generators
//	                  and tools like Scalar, Bruno, and Insomnia
//	docs/api-v1.md    the human reference
//
// Both are committed so they are reviewable in a diff: a pull request that
// changes the API shows exactly what changed for consumers, which a spec built
// only at runtime would hide.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"schautrack/internal/openapi"
)

const (
	specPath = "api/openapi.json"
	docsPath = "docs/api-v1.md"
)

func main() {
	check := flag.Bool("check", false, "verify the committed files are up to date; write nothing")
	flag.Parse()

	// Build with an empty version so the output does not churn on every
	// deployment — the committed artifacts describe the contract, not a build.
	//
	// The base URL, by contrast, is pinned to the canonical Schautrack host on
	// purpose. A running server serves its own BASE_URL here (that is what stops
	// a self-hosted instance from pointing clients at schautrack.com), but the
	// committed artifacts must be byte-stable and reviewable in a diff, so they
	// cannot depend on the environment of whoever ran this generator. Readers of
	// api/openapi.json therefore get one fixed, documented host; readers of a
	// live /api/v1/openapi.json get theirs.
	doc := openapi.Build("", openapi.CanonicalBaseURL)

	spec, err := doc.JSON()
	if err != nil {
		fail("build openapi document: %v", err)
	}
	spec = append(spec, '\n')
	docs := []byte(doc.Markdown())

	if *check {
		stale := verify(specPath, spec) | verify(docsPath, docs)
		if stale != 0 {
			fmt.Fprintln(os.Stderr, "\nRun `go run ./cmd/apidocs` and commit the result.")
			os.Exit(1)
		}
		fmt.Println("API docs are up to date.")
		return
	}

	write(specPath, spec)
	write(docsPath, docs)
	fmt.Printf("wrote %s and %s\n", specPath, docsPath)
}

// verify reports whether path differs from want. It returns 1 on a mismatch so
// callers can OR the results and report every stale file in one run rather than
// one per CI round-trip.
func verify(path string, want []byte) int {
	got, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: missing or unreadable (%v)\n", path, err)
		return 1
	}
	if string(got) != string(want) {
		fmt.Fprintf(os.Stderr, "%s: out of date with internal/openapi\n", path)
		return 1
	}
	return 0
}

func write(path string, content []byte) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fail("create %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		fail("write %s: %v", path, err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
