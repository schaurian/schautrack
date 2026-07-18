package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLatestVersionDisabled_NoPhoneHome verifies the UPDATE_CHECK_ENABLED=false
// opt-out: the handler reports no update and never performs the upstream lookup,
// so no request is made to GitHub.
func TestLatestVersionDisabled_NoPhoneHome(t *testing.T) {
	// Reset the shared cache so we can assert the disabled handler never touches it.
	latestVersion = latestVersionCache{}

	h := LatestVersion(false)
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

	// The disabled handler must not have performed the upstream lookup — the
	// cache stays pristine, proving no outbound request was attempted.
	if !latestVersion.fetchedAt.IsZero() {
		t.Errorf("cache was touched (fetchedAt=%v); update check ran despite being disabled", latestVersion.fetchedAt)
	}
}
