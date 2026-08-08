package openapi

import (
	"strings"
	"testing"
)

// TestHTMLContainsEveryOperationAndSchema is the docs-page version of the
// route-parity guarantee: an endpoint or schema missing from the rendered
// page is exactly the silent drift this package exists to prevent.
func TestHTMLContainsEveryOperationAndSchema(t *testing.T) {
	d := Build("test", "")
	page := d.HTML()

	for _, ep := range d.Operations() {
		if id := opAnchor(ep.Method, ep.Path); !strings.Contains(page, `id="`+id+`"`) {
			t.Errorf("page has no section for %s %s (anchor %q)", ep.Method, ep.Path, id)
		}
	}
	for name := range d.Components.Schemas {
		if !strings.Contains(page, `id="schema-`+name+`"`) {
			t.Errorf("page has no section for schema %s", name)
		}
	}
}

func TestOpAnchor(t *testing.T) {
	cases := []struct{ method, path, want string }{
		{"GET", "/me", "get-me"},
		{"POST", "/entries", "post-entries"},
		{"PATCH", "/entries/{id}", "patch-entries-id"},
		{"PUT", "/todos/{id}/completions/{date}", "put-todos-id-completions-date"},
	}
	for _, c := range cases {
		if got := opAnchor(c.method, c.path); got != c.want {
			t.Errorf("opAnchor(%s, %s) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestHTMLScopeChips(t *testing.T) {
	d := Build("test", "")
	page := d.HTML()

	// /openapi.json and /docs are public; /me GET needs a token but no scope;
	// PATCH /me is scoped. All three chip variants must appear.
	for _, want := range []string{"no auth", "token, any scope", "scope: settings:write"} {
		if !strings.Contains(page, want) {
			t.Errorf("page is missing a %q chip", want)
		}
	}
}

// TestHTMLHasNoMarkdownArtifacts scans the page outside code samples for
// literal markdown punctuation, which would mean some prose path skipped the
// converter.
func TestHTMLHasNoMarkdownArtifacts(t *testing.T) {
	page := stripTags(Build("test", "").HTML(), "pre", "code", "style")
	for _, artifact := range []string{"**", "## ", "```", "](#", "| --- |"} {
		if i := strings.Index(page, artifact); i >= 0 {
			lo := max(0, i-80)
			t.Errorf("page contains literal %q near: …%s…", artifact, page[lo:min(len(page), i+80)])
		}
	}
}

func TestHTMLIsDeterministicAndSelfContained(t *testing.T) {
	a, b := Build("test", "").HTML(), Build("test", "").HTML()
	if a != b {
		t.Error("two builds rendered different pages; the handler caches this, so it must be deterministic")
	}
	// External links in prose (<a href>) are fine; loading a resource is not.
	for _, forbidden := range []string{"<script", `src="http`, "@import", "url("} {
		if strings.Contains(a, forbidden) {
			t.Errorf("page contains %q — it must stay self-contained (CSP blocks external loads, scripts)", forbidden)
		}
	}
}

// TestHTMLEscapesDescriptions plants a hostile description and checks it
// cannot become markup.
func TestHTMLEscapesDescriptions(t *testing.T) {
	d := Build("test", "")
	d.Paths["/entries"].Get.Description = `evil <script>alert(1)</script> & <img src=x>`
	page := d.HTML()
	if strings.Contains(page, "<script>alert(1)</script>") || strings.Contains(page, "<img src=x>") {
		t.Error("operation description was not escaped")
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped form of the description is missing entirely")
	}
}
