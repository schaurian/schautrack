package config

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

var (
	goDirective  = regexp.MustCompile(`(?m)^go (\d+\.\d+(?:\.\d+)?)$`)
	golangImage  = regexp.MustCompile(`(?m)^FROM golang:(\d+\.\d+(?:\.\d+)?)-alpine`)
	repoRootPath = func(name string) string { return filepath.Join("..", "..", name) }
)

// TestDockerfileGoMatchesGoMod enforces the pin the Dockerfile's own comment
// claims: "Pinned to the exact patch `go.mod` requires."
//
// Nothing checked that claim, and the two silently diverged — which is not a
// tidiness problem, it is a hole in the test gate. Every CI job that compiles or
// scans Go code resolves its toolchain from `go-version-file: go.mod`, while the
// shipped binary is built by the Dockerfile's image. When those disagree, CI
// tests one Go version and production runs another, so a behaviour change
// between the two passes CI green and reaches users unobserved.
//
// That is not hypothetical. Go 1.27 stopped attaching the field name to an
// UnmarshalTypeError raised inside a custom json.Unmarshaler, which silently
// downgraded every wrong-typed field on a v1 PATCH body from `422` with
// invalid_params to a bare, misleading `400` (see nameTypeErrorField). A
// Dockerfile bump to 1.27 with go.mod left on 1.26 shipped exactly that while
// the test job, still on 1.26, stayed green.
//
// Keeping the two in lockstep means the version CI exercises is the version that
// ships. When Renovate bumps the Dockerfile, this test is what says the go
// directive has to move with it — and makes any behaviour difference show up as
// a failing test rather than as a production incident.
func TestDockerfileGoMatchesGoMod(t *testing.T) {
	goMod, err := os.ReadFile(repoRootPath("go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	dockerfile, err := os.ReadFile(repoRootPath("Dockerfile"))
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}

	modMatch := goDirective.FindSubmatch(goMod)
	if modMatch == nil {
		t.Fatal("go.mod has no `go <version>` directive")
	}
	imgMatch := golangImage.FindSubmatch(dockerfile)
	if imgMatch == nil {
		t.Fatal("Dockerfile has no `FROM golang:<version>-alpine` stage")
	}

	if got, want := string(imgMatch[1]), string(modMatch[1]); got != want {
		t.Errorf("Dockerfile builds with golang:%s-alpine but go.mod requires go %s.\n"+
			"CI resolves every Go job from go.mod, so this gap means the tested "+
			"toolchain is not the shipped one. Move both to the same patch.", got, want)
	}
}
