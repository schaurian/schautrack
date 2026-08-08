package openapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoFile resolves a repo-relative path from this package's directory.
func repoFile(t *testing.T, rel string) string {
	t.Helper()
	return filepath.Join("..", "..", rel)
}

// TestGeneratedArtifactsAreCurrent fails when api/openapi.json or
// docs/api-v1.md no longer match what internal/openapi produces.
//
// `go test ./...` already gates CI, so this makes stale documentation a build
// failure without needing anyone to remember a separate step. Changing the API
// and forgetting to regenerate is the normal failure mode; this is what catches
// it.
//
// The base URL must match the one cmd/apidocs builds with, or this test fails
// on the `servers` entry alone and says nothing useful about the rest.
func TestGeneratedArtifactsAreCurrent(t *testing.T) {
	doc := Build("", CanonicalBaseURL)

	spec, err := doc.JSON()
	if err != nil {
		t.Fatalf("build spec: %v", err)
	}
	spec = append(spec, '\n')

	cases := []struct {
		path string
		want []byte
	}{
		{"api/openapi.json", spec},
		{"docs/api-v1.md", []byte(doc.Markdown())},
	}

	for _, c := range cases {
		got, err := os.ReadFile(repoFile(t, c.path))
		if err != nil {
			t.Errorf("%s: %v — run `go run ./cmd/apidocs`", c.path, err)
			continue
		}
		if string(got) != string(c.want) {
			t.Errorf("%s is out of date with internal/openapi.\nRun `go run ./cmd/apidocs` and commit the result.", c.path)
		}
	}
}

// TestBuildIsDeterministic checks two builds produce identical bytes. Go sorts
// map keys when marshalling, but a stray time or random value in the document
// would break the CI diff check in a way that is maddening to debug — assert it
// instead.
func TestBuildIsDeterministic(t *testing.T) {
	first, err := Build("", CanonicalBaseURL).JSON()
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	second, err := Build("", CanonicalBaseURL).JSON()
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	if string(first) != string(second) {
		t.Error("Build() is not deterministic — the committed spec would churn on every regeneration")
	}
}

// TestBuildVersionAppearsInServedSpecOnly checks the build version reaches a
// served document but never the committed one.
func TestBuildVersionAppearsInServedSpecOnly(t *testing.T) {
	served := Build("v2.3.5", CanonicalBaseURL)
	if !strings.Contains(served.Info.Description, "v2.3.5") {
		t.Error("the served spec should name the build serving it")
	}
	committed := Build("", CanonicalBaseURL)
	if strings.Contains(committed.Info.Description, "Served by build") {
		t.Error("the committed spec must not carry a build stamp, or it churns on every release")
	}
}

// TestEveryOperationIsDocumented checks each operation carries the metadata the
// reference page renders. A missing summary produces an empty heading.
func TestEveryOperationIsDocumented(t *testing.T) {
	doc := Build("", CanonicalBaseURL)
	ids := map[string]string{}

	for path, item := range doc.Paths {
		for method, op := range item.Operations() {
			where := method + " " + path

			if strings.TrimSpace(op.Summary) == "" {
				t.Errorf("%s has no summary", where)
			}
			if strings.TrimSpace(op.OperationID) == "" {
				t.Errorf("%s has no operationId", where)
			}
			if len(op.Tags) == 0 {
				t.Errorf("%s has no tag, so it lands under 'Other' in the docs", where)
			}
			if len(op.Responses) == 0 {
				t.Errorf("%s documents no responses", where)
			}

			// operationId is the docs anchor and the generated client's method
			// name; a duplicate silently breaks both.
			if prev, dup := ids[op.OperationID]; dup {
				t.Errorf("operationId %q is used by both %s and %s", op.OperationID, prev, where)
			}
			ids[op.OperationID] = where

			// Every mutating operation must document a failure mode. One that
			// only lists 2xx is a spec nobody can write error handling against.
			if method != "GET" {
				if _, ok := op.Responses["400"]; !ok {
					t.Errorf("%s documents no 400 response", where)
				}
			}
		}
	}
}

// TestMarkdownRendersEveryEndpoint checks no operation is dropped by the
// renderer's tag grouping.
func TestMarkdownRendersEveryEndpoint(t *testing.T) {
	doc := Build("", CanonicalBaseURL)
	md := doc.Markdown()

	for _, op := range doc.Operations() {
		want := op.Method + " /api/v1" + op.Path
		if !strings.Contains(md, want) {
			t.Errorf("generated markdown does not document %q", want)
		}
	}
}
