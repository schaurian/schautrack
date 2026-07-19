package release

import (
	"context"
	"testing"
)

func TestNew(t *testing.T) {
	if _, err := New("github", "schaurian/schautrack", ""); err != nil {
		t.Fatalf("github: %v", err)
	}
	if _, err := New("", "schaurian/schautrack", ""); err != nil {
		t.Fatalf("default (github): %v", err)
	}
	if _, err := New("gitlab", "schauer.to/schautrack", ""); err != nil {
		t.Fatalf("gitlab: %v", err)
	}
	if _, err := New("bitbucket", "a/b", ""); err == nil {
		t.Error("unknown provider should error")
	}
	if _, err := New("github", "  ", ""); err == nil {
		t.Error("empty repo should error")
	}
}

func TestGitHubURLs(t *testing.T) {
	p, _ := New("github", "schaurian/schautrack", "")
	if got, want := p.Name(), "github"; got != want {
		t.Errorf("Name = %q, want %q", got, want)
	}
	if got, want := p.RepoURL(), "https://github.com/schaurian/schautrack"; got != want {
		t.Errorf("RepoURL = %q, want %q", got, want)
	}
	if got, want := p.IssuesURL(), "https://github.com/schaurian/schautrack/issues"; got != want {
		t.Errorf("IssuesURL = %q, want %q", got, want)
	}
	if got, want := p.NewIssueURLTemplate(), "https://github.com/schaurian/schautrack/issues/new?title={title}&body={body}"; got != want {
		t.Errorf("NewIssueURLTemplate = %q, want %q", got, want)
	}

	req, err := p.LatestReleaseRequest(context.Background())
	if err != nil {
		t.Fatalf("LatestReleaseRequest: %v", err)
	}
	if got, want := req.URL.String(), "https://api.github.com/repos/schaurian/schautrack/releases/latest"; got != want {
		t.Errorf("request URL = %q, want %q", got, want)
	}
}

func TestGitHubEnterpriseBase(t *testing.T) {
	p, _ := New("github", "org/app", "https://ghe.example.com")
	req, _ := p.LatestReleaseRequest(context.Background())
	if got, want := req.URL.String(), "https://ghe.example.com/api/v3/repos/org/app/releases/latest"; got != want {
		t.Errorf("GHE request URL = %q, want %q", got, want)
	}
	if got, want := p.RepoURL(), "https://ghe.example.com/org/app"; got != want {
		t.Errorf("GHE RepoURL = %q, want %q", got, want)
	}
}

func TestGitHubParseTag(t *testing.T) {
	p, _ := New("github", "o/r", "")
	tag, err := p.ParseLatestTag([]byte(`{"tag_name":"v2.3.5","name":"2.3.5"}`))
	if err != nil {
		t.Fatalf("ParseLatestTag: %v", err)
	}
	if tag != "2.3.5" {
		t.Errorf("tag = %q, want 2.3.5 (leading v stripped)", tag)
	}
	if _, err := p.ParseLatestTag([]byte(`not json`)); err == nil {
		t.Error("malformed body should error")
	}
}

func TestGitLabURLs(t *testing.T) {
	p, _ := New("gitlab", "schauer.to/schautrack", "")
	if got, want := p.Name(), "gitlab"; got != want {
		t.Errorf("Name = %q, want %q", got, want)
	}
	if got, want := p.RepoURL(), "https://gitlab.com/schauer.to/schautrack"; got != want {
		t.Errorf("RepoURL = %q, want %q", got, want)
	}
	if got, want := p.IssuesURL(), "https://gitlab.com/schauer.to/schautrack/-/issues"; got != want {
		t.Errorf("IssuesURL = %q, want %q", got, want)
	}
	if got, want := p.NewIssueURLTemplate(), "https://gitlab.com/schauer.to/schautrack/-/issues/new?issue[title]={title}&issue[description]={body}"; got != want {
		t.Errorf("NewIssueURLTemplate = %q, want %q", got, want)
	}

	// The project path must be URL-encoded (owner%2Frepo) in the API request.
	req, err := p.LatestReleaseRequest(context.Background())
	if err != nil {
		t.Fatalf("LatestReleaseRequest: %v", err)
	}
	if got, want := req.URL.String(), "https://gitlab.com/api/v4/projects/schauer.to%2Fschautrack/releases?per_page=1&order_by=released_at&sort=desc"; got != want {
		t.Errorf("request URL = %q, want %q", got, want)
	}
}

func TestGitLabSelfHostedBase(t *testing.T) {
	p, _ := New("gitlab", "grp/app", "https://gitlab.example.com/")
	req, _ := p.LatestReleaseRequest(context.Background())
	if got, want := req.URL.String(), "https://gitlab.example.com/api/v4/projects/grp%2Fapp/releases?per_page=1&order_by=released_at&sort=desc"; got != want {
		t.Errorf("self-hosted request URL = %q, want %q", got, want)
	}
	if got, want := p.RepoURL(), "https://gitlab.example.com/grp/app"; got != want {
		t.Errorf("self-hosted RepoURL = %q, want %q", got, want)
	}
}

func TestGitLabParseTag(t *testing.T) {
	p, _ := New("gitlab", "o/r", "")
	tag, err := p.ParseLatestTag([]byte(`[{"tag_name":"v9.9.9"},{"tag_name":"v9.9.8"}]`))
	if err != nil {
		t.Fatalf("ParseLatestTag: %v", err)
	}
	if tag != "9.9.9" {
		t.Errorf("tag = %q, want 9.9.9 (first element, v stripped)", tag)
	}
	// A repo with no releases yields "" and no error.
	tag, err = p.ParseLatestTag([]byte(`[]`))
	if err != nil || tag != "" {
		t.Errorf("empty releases: tag=%q err=%v, want \"\", nil", tag, err)
	}
}
