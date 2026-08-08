package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// servedSpecServer fetches GET /openapi.json from h and returns servers[0].url.
func servedSpecServer(t *testing.T, h *V1Handler, host string) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/openapi.json", nil)
	if host != "" {
		req.Host = host
	}
	rec := httptest.NewRecorder()
	h.MountAPIV1(nil).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var doc struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("served spec is not valid JSON: %v", err)
	}
	if len(doc.Servers) != 1 {
		t.Fatalf("served spec has %d servers, want exactly 1: %+v", len(doc.Servers), doc.Servers)
	}
	return doc.Servers[0].URL
}

// TestServedSpecPointsAtThisInstance checks the document a self-hoster's client
// reads names their own server. The previous behaviour shipped a hardcoded
// schautrack.com entry to every deployment, so Swagger UI's "Try it out" sent
// the operator's own stk_ token off-instance.
func TestServedSpecPointsAtThisInstance(t *testing.T) {
	cases := []struct {
		name, baseURL, want string
	}{
		{"configured self-hosted instance", "https://track.example.com", "https://track.example.com/api/v1"},
		{"trailing slash", "https://track.example.com/", "https://track.example.com/api/v1"},
		{"unconfigured instance serves a relative url", "", "/api/v1"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &V1Handler{BuildVersion: "test", BaseURL: c.baseURL}
			if got := servedSpecServer(t, h, ""); got != c.want {
				t.Errorf("servers[0].url = %q, want %q", got, c.want)
			}
		})
	}
}

// TestSpecCacheDoesNotLeakAcrossInstances is the sync.Once half of the fix.
//
// The document used to be memoized in package-level vars, so the first handler
// to serve it fixed the bytes — and therefore the servers URL — for every other
// handler in the process. Two instances in one process (tests, an embedding
// binary, or any future multi-tenant wiring) would then read each other's host.
// The cache now lives on the handler; this asserts it, in both orders, so the
// test cannot pass merely because one handler happened to warm up first.
func TestSpecCacheDoesNotLeakAcrossInstances(t *testing.T) {
	first := &V1Handler{BaseURL: "https://first.example.com"}
	second := &V1Handler{BaseURL: "https://second.example.org"}

	if got, want := servedSpecServer(t, first, ""), "https://first.example.com/api/v1"; got != want {
		t.Fatalf("first instance: servers[0].url = %q, want %q", got, want)
	}
	if got, want := servedSpecServer(t, second, ""), "https://second.example.org/api/v1"; got != want {
		t.Errorf("second instance served the first instance's host: %q, want %q", got, want)
	}
	// And back again: the second call must not have poisoned the first either.
	if got, want := servedSpecServer(t, first, ""), "https://first.example.com/api/v1"; got != want {
		t.Errorf("first instance after the second served: servers[0].url = %q, want %q", got, want)
	}
}

// TestSpecCacheIsStableAcrossRequests checks the memoized document is reused
// unchanged, and in particular that nothing request-derived reaches it: a
// caller sending an arbitrary Host header must not be able to rewrite the
// servers URL that the next caller reads.
func TestSpecCacheIsStableAcrossRequests(t *testing.T) {
	h := &V1Handler{BaseURL: "https://track.example.com"}
	const want = "https://track.example.com/api/v1"

	if got := servedSpecServer(t, h, "attacker.example.net"); got != want {
		t.Fatalf("first request with a spoofed Host: servers[0].url = %q, want %q", got, want)
	}
	if got := servedSpecServer(t, h, ""); got != want {
		t.Errorf("second request: servers[0].url = %q, want %q — a Host header reached the cached document", got, want)
	}
}
