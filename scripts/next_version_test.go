// Package scripts hosts build-time behavioural assertions about the shell
// scripts under scripts/ that Go's test runner can enforce, so they ride the
// existing `go test ./...` CI job. internal/config/readme_env_test.go and
// internal/ui/client_controls_test.go do the same thing for the README's
// environment-variable table and the client's control usage, respectively.
package scripts

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// nextVersionScript is next-version.sh's absolute path, so the script under
// test can be invoked with a temp directory as its working directory (it
// shells out to `git describe`/`git log` against the CURRENT directory, not
// wherever the script itself lives).
var nextVersionScript = mustAbs("next-version.sh")

func mustAbs(name string) string {
	abs, err := filepath.Abs(name)
	if err != nil {
		panic(err)
	}
	return abs
}

// runGit runs a git command in dir with a fixed, isolated identity: no host
// or user gitconfig (GIT_CONFIG_GLOBAL/_SYSTEM point at a file that does not
// exist, which git treats as an absent config, exactly like a bare $HOME) and
// no commit signing, so this test behaves the same on a contributor's machine
// and on a clean CI runner regardless of global git config.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+filepath.Join(dir, ".unused-gitconfig"),
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out.String())
	}
}

// newTaggedRepo creates a temp git repo with one commit tagged baseTag, ready
// for test-specific commits on top of it.
func newTaggedRepo(t *testing.T, baseTag string) string {
	t.Helper()
	dir := t.TempDir()
	runGit(t, dir, "init", "-q", "-b", "main")
	runGit(t, dir, "commit", "-q", "--allow-empty", "-m", "chore: initial commit")
	runGit(t, dir, "tag", baseTag)
	return dir
}

// runNextVersion runs next-version.sh with dir as its working directory and
// returns trimmed stdout.
func runNextVersion(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("sh", nextVersionScript)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("sh %s: %v\nstderr: %s", nextVersionScript, err, stderr.String())
	}
	return string(bytes.TrimSpace(stdout.Bytes()))
}

// TestNextVersionScopedAndBangCommits pins the exact bug that shipped two
// wrong releases: next-version.sh's bump regexes had no optional scope group,
// so a Conventional Commits subject with a scope — `feat(ai): add Google
// Gemini provider` — fell through the feat branch into the patch branch and
// released v2.5.5 instead of v2.6.0. The same gap under-versioned the welcome
// tour as v2.4.2 instead of v2.5.0 on 2026-08-05.
//
// This exercises the real script end-to-end against a real git repo (tag +
// commits), not a regex-string assertion, because the bug was in how the
// regex was *applied* to real commit history via `git log` and `grep`, and a
// unit test of the pattern alone would not have caught the missing `feat(ai):`
// case either.
func TestNextVersionScopedAndBangCommits(t *testing.T) {
	tests := []struct {
		name    string
		commits []string
		want    string
	}{
		{
			name:    "unscoped feat is a minor bump",
			commits: []string{"feat: add widget"},
			want:    "1.3.0",
		},
		{
			name:    "scoped feat is a minor bump",
			commits: []string{"feat(ai): add Google Gemini provider"},
			want:    "1.3.0",
		},
		{
			name:    "bang feat is a major bump",
			commits: []string{"feat!: drop legacy v0 endpoints"},
			want:    "2.0.0",
		},
		{
			name:    "unscoped fix is a patch bump",
			commits: []string{"fix: correct rounding"},
			want:    "1.2.4",
		},
		{
			name:    "scoped fix is a patch bump",
			commits: []string{"fix(deps): bump go-chi/chi"},
			want:    "1.2.4",
		},
		{
			name:    "scoped chore is a patch bump",
			commits: []string{"chore(deps): bump renovate config"},
			want:    "1.2.4",
		},
		{
			name:    "no conventional prefix defaults to patch",
			commits: []string{"update readme wording"},
			want:    "1.2.4",
		},
		{
			name: "a scoped feat beats several fixes regardless of order",
			commits: []string{
				"fix: a",
				"fix(deps): b",
				"feat(ai): add Google Gemini provider",
				"chore: c",
			},
			want: "1.3.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := newTaggedRepo(t, "v1.2.3")
			for _, subject := range tt.commits {
				runGit(t, dir, "commit", "-q", "--allow-empty", "-m", subject)
			}
			got := runNextVersion(t, dir)
			if got != tt.want {
				t.Errorf("commits %v: next-version.sh printed %q, want %q", tt.commits, got, tt.want)
			}
		})
	}
}
