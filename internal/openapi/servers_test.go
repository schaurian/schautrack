package openapi

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestServersFollowTheInstance is the regression guard for the bug where every
// instance shipped a hardcoded servers list naming schautrack.com. On a
// self-hosted deployment that sent Swagger UI's "Try it out" — and with it the
// caller's long-lived stk_ bearer token — to a host the operator does not own.
func TestServersFollowTheInstance(t *testing.T) {
	cases := []struct {
		name, baseURL, want string
	}{
		{"self-hosted instance", "https://track.example.com", "https://track.example.com/api/v1"},
		{"trailing slash is not doubled", "https://track.example.com/", "https://track.example.com/api/v1"},
		{"surrounding whitespace is ignored", "  https://track.example.com  ", "https://track.example.com/api/v1"},
		{"instance served under a path prefix", "https://example.com/track", "https://example.com/track/api/v1"},
		{"plain http development instance", "http://localhost:3000", "http://localhost:3000/api/v1"},
		{"unconfigured base url falls back to relative", "", "/api/v1"},
		{"the canonical host is just another base url", CanonicalBaseURL, "https://schautrack.com/api/v1"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Build("", c.baseURL).Servers

			// Exactly one entry: a second one is a second place a client could
			// send a token, and clients pick servers[0] silently.
			if len(got) != 1 {
				t.Fatalf("got %d servers, want exactly 1: %+v", len(got), got)
			}
			if got[0].URL != c.want {
				t.Errorf("servers[0].url = %q, want %q", got[0].URL, c.want)
			}
			if got[0].Description == "" {
				t.Error("servers[0] has no description")
			}
		})
	}
}

// TestServersNeverNameAnotherInstance checks the failure mode directly: a
// configured instance must not mention schautrack.com anywhere in its servers
// block, however the document is later edited.
func TestServersNeverNameAnotherInstance(t *testing.T) {
	for _, base := range []string{"https://track.example.com", "https://nutrition.internal.lan:8443", ""} {
		doc := Build("v1.2.3", base)
		for _, s := range doc.Servers {
			if strings.Contains(s.URL, "schautrack.com") {
				t.Errorf("base %q: servers entry %q names the upstream host", base, s.URL)
			}
		}
	}
}

// TestServersSurviveJSONRoundTrip checks the URL a client actually reads, not
// just the Go value — servers is what tooling dereferences, so the serialized
// form is the contract.
func TestServersSurviveJSONRoundTrip(t *testing.T) {
	raw, err := Build("", "https://track.example.com").JSON()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	var doc struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	if len(doc.Servers) != 1 || doc.Servers[0].URL != "https://track.example.com/api/v1" {
		t.Fatalf("serialized servers = %+v, want one entry https://track.example.com/api/v1", doc.Servers)
	}
}

// TestProblemTypesAreDocumentedAsIdentifiers checks the description explains
// why the RFC 9457 `type` URIs keep naming schautrack.com on every instance
// while the servers URL does not. Without that sentence the two look like the
// same oversight, and a self-hoster "fixing" the type URIs would break clients
// that branch on them.
func TestProblemTypesAreDocumentedAsIdentifiers(t *testing.T) {
	desc := Build("", "https://track.example.com").Info.Description
	for _, want := range []string{"stable identifiers, not endpoints", "self-hosted"} {
		if !strings.Contains(desc, want) {
			t.Errorf("the API description does not explain the problem type URIs: missing %q", want)
		}
	}
}
