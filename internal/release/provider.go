// Package release abstracts "what is the newest release, and where do users file
// issues" across hosting platforms (GitHub, GitLab). It only builds requests and
// URLs and parses release payloads; the caller owns the HTTP client, caching and
// the UPDATE_CHECK_ENABLED opt-out.
package release

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const userAgent = "schautrack-server"

// Provider locates the latest release and the human-facing repo/issue URLs for a
// configured repository on a specific hosting platform.
type Provider interface {
	// Name is the platform slug exposed to the client ("github" | "gitlab").
	Name() string
	// LatestReleaseRequest builds the API request that returns the newest release.
	LatestReleaseRequest(ctx context.Context) (*http.Request, error)
	// ParseLatestTag extracts the newest release tag from the API response body,
	// with any leading "v" stripped. It returns "" (no error) when the repository
	// has no releases yet.
	ParseLatestTag(body []byte) (string, error)
	// RepoURL is the human-facing repository URL.
	RepoURL() string
	// IssuesURL is the human-facing open-issues list URL.
	IssuesURL() string
	// NewIssueURLTemplate is the human-facing "new issue" URL containing the literal
	// tokens {title} and {body}; the client substitutes URL-encoded values.
	NewIssueURLTemplate() string
}

// New builds a Provider from configuration. provider defaults to "github". repo is
// "owner/repo" (GitLab also accepts nested "group/subgroup/project"). baseURL
// overrides the default host for self-hosted GitHub Enterprise / GitLab instances.
func New(provider, repo, baseURL string) (Provider, error) {
	repo = strings.Trim(strings.TrimSpace(repo), "/")
	if repo == "" {
		return nil, fmt.Errorf("release: repo is required (set UPDATE_REPO=owner/repo)")
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "github":
		return newGitHub(repo, baseURL), nil
	case "gitlab":
		return newGitLab(repo, baseURL), nil
	default:
		return nil, fmt.Errorf("release: unknown provider %q (want github|gitlab)", provider)
	}
}

func normalizeTag(tag string) string {
	return strings.TrimPrefix(strings.TrimSpace(tag), "v")
}

// --- GitHub -----------------------------------------------------------------

type github struct {
	repo    string // owner/repo
	webBase string // https://github.com
	apiBase string // https://api.github.com  (or https://host/api/v3 for Enterprise)
}

func newGitHub(repo, baseURL string) *github {
	webBase := "https://github.com"
	apiBase := "https://api.github.com"
	if b := strings.TrimRight(strings.TrimSpace(baseURL), "/"); b != "" {
		// GitHub Enterprise: the web host is the base and its API lives at /api/v3.
		webBase = b
		apiBase = b + "/api/v3"
	}
	return &github{repo: repo, webBase: webBase, apiBase: apiBase}
}

func (g *github) Name() string { return "github" }

func (g *github) LatestReleaseRequest(ctx context.Context) (*http.Request, error) {
	u := fmt.Sprintf("%s/repos/%s/releases/latest", g.apiBase, g.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}

func (g *github) ParseLatestTag(body []byte) (string, error) {
	var v struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", err
	}
	return normalizeTag(v.TagName), nil
}

func (g *github) RepoURL() string   { return g.webBase + "/" + g.repo }
func (g *github) IssuesURL() string { return g.RepoURL() + "/issues" }
func (g *github) NewIssueURLTemplate() string {
	return g.RepoURL() + "/issues/new?title={title}&body={body}"
}

// --- GitLab -----------------------------------------------------------------

type gitlab struct {
	repo    string // group/project (may be nested)
	webBase string // https://gitlab.com
	apiBase string // https://gitlab.com/api/v4
}

func newGitLab(repo, baseURL string) *gitlab {
	webBase := "https://gitlab.com"
	if b := strings.TrimRight(strings.TrimSpace(baseURL), "/"); b != "" {
		webBase = b
	}
	return &gitlab{repo: repo, webBase: webBase, apiBase: webBase + "/api/v4"}
}

func (g *gitlab) Name() string { return "gitlab" }

func (g *gitlab) LatestReleaseRequest(ctx context.Context) (*http.Request, error) {
	// GitLab identifies a project by its URL-encoded path. Fetch the most recent
	// release (array response) rather than /releases/permalink/latest so we don't
	// depend on a newer GitLab version.
	u := fmt.Sprintf("%s/projects/%s/releases?per_page=1&order_by=released_at&sort=desc",
		g.apiBase, url.PathEscape(g.repo))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	return req, nil
}

func (g *gitlab) ParseLatestTag(body []byte) (string, error) {
	var v []struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", err
	}
	if len(v) == 0 {
		return "", nil
	}
	return normalizeTag(v[0].TagName), nil
}

func (g *gitlab) RepoURL() string   { return g.webBase + "/" + g.repo }
func (g *gitlab) IssuesURL() string { return g.RepoURL() + "/-/issues" }
func (g *gitlab) NewIssueURLTemplate() string {
	return g.RepoURL() + "/-/issues/new?issue[title]={title}&issue[description]={body}"
}
