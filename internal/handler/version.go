package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"schautrack/internal/release"
)

const (
	latestVersionTTL    = time.Hour
	latestVersionErrTTL = 5 * time.Minute
	latestVersionMaxLen = 1 << 20 // cap the release payload we read (1 MiB)
)

type latestVersionCache struct {
	mu        sync.Mutex
	tag       string
	fetchedAt time.Time
	err       bool
}

var latestVersion latestVersionCache

// LatestVersion reports the newest published release plus the configured
// repository/issue URLs, so the client can flag an outdated instance and offer a
// pre-filled "Report an Issue" link. When enabled is false the handler never
// contacts the provider and reports latest=null — the opt-out for
// self-hosted/air-gapped deployments (UPDATE_CHECK_ENABLED=false). The repo/issue
// URLs come from static config and are always returned so issue reporting works
// regardless of the update check.
func LatestVersion(p release.Provider, enabled bool) http.HandlerFunc {
	client := &http.Client{Timeout: 5 * time.Second}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=600")

		var latest any
		if enabled {
			if tag := latestVersion.lookup(r.Context(), client, p); tag != "" {
				latest = tag
			}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"latest":              latest,
			"provider":            p.Name(),
			"repoUrl":             p.RepoURL(),
			"issuesUrl":           p.IssuesURL(),
			"newIssueUrlTemplate": p.NewIssueURLTemplate(),
		})
	}
}

func (c *latestVersionCache) lookup(ctx context.Context, client *http.Client, p release.Provider) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	ttl := latestVersionTTL
	if c.err {
		ttl = latestVersionErrTTL
	}
	if !c.fetchedAt.IsZero() && time.Since(c.fetchedAt) < ttl {
		return c.tag
	}

	// Every early return records the attempt (fetchedAt/err) so the TTL applies and
	// we don't hammer the provider on repeated failures. c.tag (the last good value)
	// is preserved across errors.
	fail := func() string {
		c.fetchedAt = time.Now()
		c.err = true
		return c.tag
	}

	req, err := p.LatestReleaseRequest(ctx)
	if err != nil {
		return fail()
	}

	resp, err := client.Do(req)
	if err != nil {
		return fail()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fail()
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, latestVersionMaxLen))
	if err != nil {
		return fail()
	}

	tag, err := p.ParseLatestTag(body)
	if err != nil {
		return fail()
	}

	c.tag = tag
	c.fetchedAt = time.Now()
	c.err = false
	return c.tag
}
