package openapi

import (
	"strings"
	"testing"
)

func TestRenderInline(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", "hello world", "hello world"},
		{"escapes html", "a <b> & c", "a &lt;b&gt; &amp; c"},
		{"code", "send `POST /entries` now", "send <code>POST /entries</code> now"},
		{"bold", "this is **important** here", "this is <strong>important</strong> here"},
		{"italic", "servers *is* an endpoint", "servers <em>is</em> an endpoint"},
		{"bold then italic", "**bold** and *slanted*", "<strong>bold</strong> and <em>slanted</em>"},
		{"link", "see [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)",
			`see <a href="https://www.rfc-editor.org/rfc/rfc9457">RFC 9457</a>`},
		{"markdown inside code is literal", "use `**not bold**` here",
			"use <code>**not bold**</code> here"},
		{"html inside code is escaped", "a `<script>` tag", "a <code>&lt;script&gt;</code> tag"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := renderInline(c.in); got != c.want {
				t.Errorf("renderInline(%q)\n got %q\nwant %q", c.in, got, c.want)
			}
		})
	}
}

func TestRenderProse(t *testing.T) {
	cases := []struct {
		name, in string
		want     []string // substrings that must appear, in order
	}{
		{"heading gets anchor", "## Retrying safely",
			[]string{`<h2 id="retrying-safely">Retrying safely</h2>`}},
		{"h3 and h4", "### One\n\n#### Two",
			[]string{`<h3 id="one">One</h3>`, `<h4 id="two">Two</h4>`}},
		{"paragraph", "line one\nline two\n\nsecond para",
			[]string{"<p>line one line two</p>", "<p>second para</p>"}},
		{"fenced code kept literal", "```\nAuthorization: Bearer stk_x\n**raw**\n```",
			[]string{"<pre><code>Authorization: Bearer stk_x\n**raw**</code></pre>"}},
		{"bullet list", "- first item\n- second item",
			[]string{"<ul>", "<li>first item</li>", "<li>second item</li>", "</ul>"}},
		{"table with separator row dropped", "| Scope | Grants |\n| --- | --- |\n| `a:read` | reads |",
			[]string{"<table>", "<th>Scope</th>", "<td><code>a:read</code></td>", "</table>"}},
		{"hr dropped", "before\n\n---\n\nafter",
			[]string{"<p>before</p>", "<p>after</p>"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := renderProse(c.in)
			pos := 0
			for _, want := range c.want {
				i := strings.Index(got[pos:], want)
				if i < 0 {
					t.Fatalf("renderProse(%q):\nmissing (or out of order) %q\nin %q", c.in, want, got)
				}
				pos += i + len(want)
			}
			if c.name == "hr dropped" && strings.Contains(got, "---") {
				t.Errorf("horizontal rule leaked into output: %q", got)
			}
		})
	}
}

// TestSpecProseRendersClean renders the real document's prose and asserts no
// markdown construct survives as literal text — a new construct in the spec
// prose must extend the converter, not render raw.
func TestSpecProseRendersClean(t *testing.T) {
	d := Build("test", "")
	pages := []string{renderProse(d.Info.Description)}
	for _, item := range d.Paths {
		for _, op := range item.Operations() {
			if op.Description != "" {
				pages = append(pages, renderProse(op.Description))
			}
		}
	}
	for _, html := range pages {
		// Strip code blocks/spans first: literal markdown is fine inside them.
		stripped := stripTags(html, "pre", "code")
		for _, artifact := range []string{"**", "## ", "```", "](", "| --- |"} {
			if strings.Contains(stripped, artifact) {
				t.Errorf("rendered prose still contains literal %q:\n%s", artifact, stripped)
			}
		}
	}
}

// stripTags removes the content of the named elements (non-nested, which is
// all the converter emits) so assertions can ignore code samples.
func stripTags(s string, tags ...string) string {
	for _, tag := range tags {
		for {
			start := strings.Index(s, "<"+tag)
			if start < 0 {
				break
			}
			end := strings.Index(s[start:], "</"+tag+">")
			if end < 0 {
				break
			}
			s = s[:start] + s[start+end+len(tag)+3:]
		}
	}
	return s
}
