package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"schautrack/internal/release"
)

func githubProvider(t *testing.T, baseURL string) release.Provider {
	t.Helper()
	p, err := release.New("github", "schaurian/schautrack", baseURL)
	if err != nil {
		t.Fatalf("release.New: %v", err)
	}
	return p
}

// TestLatestVersionDisabled_NoPhoneHome verifies the UPDATE_CHECK_ENABLED=false
// opt-out: the handler reports no update and never performs the upstream lookup,
// so no request is made to the provider. The repo/issue URLs are still returned.
func TestLatestVersionDisabled_NoPhoneHome(t *testing.T) {
	// Reset the shared cache so we can assert the disabled handler never touches it.
	latestVersion = latestVersionCache{}

	h := LatestVersion(githubProvider(t, ""), false)
	r := httptest.NewRequest("GET", "/api/latest-version", nil)
	w := httptest.NewRecorder()
	h(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if v, ok := resp["latest"]; !ok || v != nil {
		t.Errorf("latest = %v, want nil", v)
	}
	// URLs are static config and must be present even with the check disabled, so
	// the "Report an Issue" link keeps working on air-gapped deployments.
	if resp["repoUrl"] != "https://github.com/schaurian/schautrack" {
		t.Errorf("repoUrl = %v", resp["repoUrl"])
	}
	if resp["issuesUrl"] != "https://github.com/schaurian/schautrack/issues" {
		t.Errorf("issuesUrl = %v", resp["issuesUrl"])
	}
	if resp["newIssueUrlTemplate"] == nil || resp["provider"] != "github" {
		t.Errorf("provider/newIssueUrlTemplate missing: %v", resp)
	}

	// The disabled handler must not have performed the upstream lookup — the
	// cache stays pristine, proving no outbound request was attempted.
	if !latestVersion.fetchedAt.IsZero() {
		t.Errorf("cache was touched (fetchedAt=%v); update check ran despite being disabled", latestVersion.fetchedAt)
	}
}

// TestLatestVersionEnabled_FetchesTag drives the enabled path through a fake
// provider API and asserts the parsed tag surfaces in the response.
func TestLatestVersionEnabled_FetchesTag(t *testing.T) {
	latestVersion = latestVersionCache{}

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/api/v3/repos/schaurian/schautrack/releases/latest" {
			t.Errorf("unexpected upstream path %q", r.URL.Path)
		}
		w.Write([]byte(`{"tag_name":"v9.9.9"}`))
	}))
	defer srv.Close()

	// Point the GitHub provider at the fake server via the Enterprise base override.
	h := LatestVersion(githubProvider(t, srv.URL), true)

	do := func() map[string]any {
		r := httptest.NewRequest("GET", "/api/latest-version", nil)
		w := httptest.NewRecorder()
		h(w, r)
		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp
	}

	if got := do()["latest"]; got != "9.9.9" {
		t.Errorf("latest = %v, want 9.9.9", got)
	}
	// A second call within the TTL is served from cache — no extra upstream hit.
	do()
	if hits != 1 {
		t.Errorf("upstream hits = %d, want 1 (second call should be cached)", hits)
	}
}
