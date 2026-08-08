package openapi

import (
	"fmt"
	"html"
	"sort"
	"strings"
)

// HTML renders the document as a self-contained reference page for
// GET /api/v1/docs — the human-readable sibling of the served openapi.json.
//
// Zero JavaScript and one inline <style> block, deliberately: the app's
// Content-Security-Policy allows only same-origin scripts and inline styles,
// so this page needs no CSP exception, no vendored viewer bundle, and no CDN.
// Links to the machine-readable spec are relative ("openapi.json"), so they
// resolve against whichever instance served the page.
//
// Like Markdown(), everything derives from the typed document, and the tests
// in html_test.go fail if an operation or schema is missing from the page.
func (d *Document) HTML() string {
	var b strings.Builder

	b.WriteString("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	fmt.Fprintf(&b, "<title>%s — reference</title>\n", html.EscapeString(d.Info.Title))
	b.WriteString("<style>" + docsCSS + "</style></head><body>\n<div class=\"layout\">\n")

	d.htmlNav(&b)

	b.WriteString("<main>\n<header>\n")
	fmt.Fprintf(&b, "<h1>%s</h1>\n<div class=\"meta\">", html.EscapeString(d.Info.Title))
	fmt.Fprintf(&b, `<span class="pill v">contract %s</span>`, html.EscapeString(d.Info.Version))
	fmt.Fprintf(&b, `<span class="pill">OpenAPI %s</span>`, html.EscapeString(d.OpenAPI))
	if len(d.Servers) > 0 {
		fmt.Fprintf(&b, `<span class="pill">server <code>%s</code></span>`, html.EscapeString(d.Servers[0].URL))
	}
	b.WriteString(`<a href="openapi.json">openapi.json</a></div>` + "\n")
	if d.Info.Summary != "" {
		fmt.Fprintf(&b, "<p class=\"tagdesc\">%s</p>\n", renderInline(d.Info.Summary))
	}
	b.WriteString("</header>\n")

	b.WriteString("<section class=\"intro\">\n" + renderProse(d.Info.Description) + "\n</section>\n")

	d.htmlEndpoints(&b)
	d.htmlSchemas(&b)

	fmt.Fprintf(&b, "<footer class=\"meta\">One day at a time · %s reference · <a href=\"openapi.json\">machine-readable spec</a></footer>\n",
		html.EscapeString(d.Info.Title))
	b.WriteString("</main>\n</div>\n</body></html>\n")
	return b.String()
}

// opAnchor is the fragment id of one operation's section: method and path,
// lowercased, slashes to dashes, parameter braces dropped — "post-entries",
// "patch-entries-id".
func opAnchor(method, path string) string {
	s := strings.ToLower(method + path)
	s = strings.NewReplacer("/", "-", "{", "", "}", "").Replace(s)
	return s
}

func (d *Document) htmlNav(b *strings.Builder) {
	order, groups := d.byTag()
	b.WriteString("<nav><div class=\"navtitle\">Endpoints</div>\n")
	for _, tag := range order {
		fmt.Fprintf(b, "<div class=\"navgroup\">%s</div>\n", html.EscapeString(tag))
		for _, t := range groups[tag] {
			fmt.Fprintf(b, "<a href=\"#%s\"><span class=\"m m-%s\">%s</span><span class=\"p\">%s</span></a>\n",
				opAnchor(t.Method, t.Path), strings.ToLower(t.Method), t.Method, html.EscapeString(t.Path))
		}
	}
	b.WriteString("<div class=\"navgroup\">Reference</div>\n<a href=\"#schemas\"><span class=\"p\">Schemas</span></a>\n</nav>\n")
}

func (d *Document) htmlEndpoints(b *strings.Builder) {
	order, groups := d.byTag()
	tagDesc := map[string]string{}
	for _, t := range d.Tags {
		tagDesc[t.Name] = t.Description
	}

	for _, tag := range order {
		fmt.Fprintf(b, "<section class=\"tag\"><h2 id=\"tag-%s\">%s</h2>\n", anchor(tag), html.EscapeString(tag))
		if td := tagDesc[tag]; td != "" {
			fmt.Fprintf(b, "<p class=\"tagdesc\">%s</p>\n", renderInline(td))
		}
		for _, t := range groups[tag] {
			d.htmlOperation(b, t)
		}
		b.WriteString("</section>\n")
	}
}

func (d *Document) htmlOperation(b *strings.Builder, t taggedOp) {
	op := t.Op
	method := strings.ToLower(t.Method)

	fmt.Fprintf(b, "<article class=\"op\" id=\"%s\">\n", opAnchor(t.Method, t.Path))
	fmt.Fprintf(b, "<div class=\"opline\"><span class=\"badge m-%s\">%s</span><code class=\"path\">%s</code>%s</div>\n",
		method, t.Method, html.EscapeString(t.Path), scopeChip(op))
	fmt.Fprintf(b, "<h3>%s</h3>\n", html.EscapeString(op.Summary))
	if op.Description != "" {
		b.WriteString("<div class=\"opdesc\">\n" + renderProse(op.Description) + "\n</div>\n")
	}

	if len(op.Parameters) > 0 {
		params := append([]Parameter(nil), op.Parameters...)
		sort.SliceStable(params, func(i, j int) bool {
			// Path parameters before query parameters: they are part of the
			// URL the reader just saw. Same ordering as the Markdown docs.
			return params[i].In == "path" && params[j].In != "path"
		})
		b.WriteString("<h4>Parameters</h4><div class=\"tblwrap\"><table><tr><th>Name</th><th>In</th><th>Description</th></tr>")
		for _, p := range params {
			req := ""
			if p.Required {
				req = ` <span class="req">required</span>`
			}
			desc := p.Description
			if desc == "" && p.Schema != nil {
				desc = p.Schema.Description
			}
			fmt.Fprintf(b, "<tr><td><code>%s</code>%s</td><td class=\"muted\">%s</td><td>%s</td></tr>",
				html.EscapeString(p.Name), req, html.EscapeString(p.In), renderInline(desc))
		}
		b.WriteString("</table></div>\n")
	}

	if op.RequestBody != nil {
		if name := bodySchemaName(op.RequestBody.Content); name != "" {
			req := "optional"
			if op.RequestBody.Required {
				req = "required"
			}
			fmt.Fprintf(b, "<h4>Request body — <a href=\"#schema-%s\">%s</a> (%s)</h4>\n", name, name, req)
			if s := d.Components.Schemas[name]; s != nil && len(s.Properties) > 0 {
				b.WriteString(htmlFieldTable(s))
			}
		}
	}

	codes := make([]string, 0, len(op.Responses))
	for code := range op.Responses {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	b.WriteString("<h4>Responses</h4><div class=\"tblwrap\"><table><tr><th>Status</th><th>Body</th><th>Description</th></tr>")
	for _, code := range codes {
		resp := op.Responses[code]
		body := "—"
		if name := bodySchemaName(resp.Content); name != "" {
			body = fmt.Sprintf("<a href=\"#schema-%s\">%s</a>", name, name)
		}
		class := "err"
		if strings.HasPrefix(code, "2") {
			class = "ok"
		}
		fmt.Fprintf(b, "<tr><td><span class=\"code %s\">%s</span></td><td class=\"type\">%s</td><td>%s</td></tr>",
			class, code, body, renderInline(resp.Description))
	}
	b.WriteString("</table></div>\n</article>\n")
}

// scopeChip mirrors the Markdown scope line: a named scope, "no auth" for the
// public endpoints (an explicit empty security requirement), or a valid token
// with no particular scope.
func scopeChip(op *Operation) string {
	if op.Scope != "" {
		return `<span class="scope">scope: ` + html.EscapeString(op.Scope) + `</span>`
	}
	if len(op.Security) == 1 && len(op.Security[0]) == 0 {
		return `<span class="scope open">no auth</span>`
	}
	return `<span class="scope">token, any scope</span>`
}

func (d *Document) htmlSchemas(b *strings.Builder) {
	b.WriteString("<section class=\"tag\"><h2 id=\"schemas\">Schemas</h2>\n")
	for _, name := range sortedKeys(d.Components.Schemas) {
		s := d.Components.Schemas[name]
		fmt.Fprintf(b, "<article class=\"op schema\" id=\"schema-%s\">\n<h3>%s</h3>\n", name, name)
		if s.Description != "" {
			fmt.Fprintf(b, "<div class=\"opdesc\">%s</div>\n", renderInline(s.Description))
		}
		if len(s.Properties) == 0 {
			b.WriteString("<p class=\"tagdesc\">Free-form object; see <a href=\"openapi.json\">openapi.json</a> for the served shape.</p>\n")
		} else {
			writeHTMLFieldTables(b, s, "")
		}
		b.WriteString("</article>\n")
	}
	b.WriteString("</section>\n")
}

// writeHTMLFieldTables renders one schema's fields, then recurses into inline
// objects exactly as the Markdown writeFieldTable does (#393): a $ref links to
// its own section, but an inline object's fields exist nowhere else, so they
// are expanded here under a dotted heading ("Me.user").
func writeHTMLFieldTables(b *strings.Builder, s *Schema, prefix string) {
	b.WriteString(htmlFieldTable(s))
	for _, field := range sortedKeys(s.Properties) {
		p := s.Properties[field]
		if p == nil || p.Ref != "" || len(p.Properties) == 0 {
			continue
		}
		path := field
		if prefix != "" {
			path = prefix + "." + field
		}
		fmt.Fprintf(b, "<h4 class=\"sub\">%s</h4>\n", html.EscapeString(path))
		if p.Description != "" {
			fmt.Fprintf(b, "<p class=\"tagdesc\">%s</p>\n", renderInline(p.Description))
		}
		writeHTMLFieldTables(b, p, path)
	}
}

// htmlFieldTable renders the top-level fields of one object schema.
func htmlFieldTable(s *Schema) string {
	required := map[string]bool{}
	for _, r := range s.Required {
		required[r] = true
	}
	var b strings.Builder
	b.WriteString("<div class=\"tblwrap\"><table><tr><th>Field</th><th>Type</th><th>Description</th></tr>")
	for _, field := range sortedKeys(s.Properties) {
		p := s.Properties[field]
		req := ""
		if required[field] {
			req = ` <span class="req">required</span>`
		}
		fmt.Fprintf(&b, "<tr><td><code>%s</code>%s</td><td class=\"type\">%s</td><td>%s</td></tr>",
			html.EscapeString(field), req, htmlTypeName(p), renderInline(p.Description))
	}
	b.WriteString("</table></div>\n")
	return b.String()
}

// htmlTypeName is typeName for the HTML page: references become links to the
// schema section, enums render as their members, arrays and null-unions are
// spelled out.
func htmlTypeName(s *Schema) string {
	if s == nil {
		return ""
	}
	if name, ok := strings.CutPrefix(s.Ref, "#/components/schemas/"); ok {
		return fmt.Sprintf("<a href=\"#schema-%s\">%s</a>", name, name)
	}
	if len(s.AnyOf) > 0 {
		var parts []string
		for _, alt := range s.AnyOf {
			parts = append(parts, htmlTypeName(alt))
		}
		return strings.Join(parts, " or ")
	}
	if len(s.Enum) > 0 {
		var parts []string
		for _, v := range s.Enum {
			if v == nil {
				parts = append(parts, "<code>null</code>")
				continue
			}
			parts = append(parts, fmt.Sprintf("<code>%s</code>", html.EscapeString(fmt.Sprintf("%v", v))))
		}
		return strings.Join(parts, " | ")
	}
	switch t := s.Type.(type) {
	case string:
		if t == "array" {
			return "array of " + htmlTypeName(s.Items)
		}
		if s.Format != "" {
			return fmt.Sprintf("<code>%s</code> <span class=\"fmt\">(%s)</span>", t, html.EscapeString(s.Format))
		}
		return "<code>" + t + "</code>"
	case []string:
		var parts []string
		for _, one := range t {
			parts = append(parts, "<code>"+one+"</code>")
		}
		return strings.Join(parts, " or ")
	}
	return "<code>object</code>"
}

// docsCSS is the page's entire stylesheet. Flat material, dark-only, the
// app's palette; no gradients, no glows, and nothing loaded from anywhere.
// The nav column is intentionally NOT sticky: position:sticky with its own
// scrollbar on this page reproducibly froze Chromium's renderer during
// design review.
const docsCSS = `
:root {
  --bg: #070d1a; --surface: #0a1220; --surface2: #0d1526;
  --border: rgba(255,255,255,.08); --text: #c3ccdd; --bright: #e8ecf4;
  --muted: #7d8aa0; --blue: #0ea5e9; --purple: #a855f7;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif; }
a { color: var(--blue); text-decoration: none; }
a:hover { text-decoration: underline; }
code { font-family: var(--mono); font-size: .875em; background: var(--surface2);
  padding: .15em .4em; border-radius: 4px; color: var(--bright); }
pre { background: var(--surface2); border: 1px solid var(--border); border-radius: 8px;
  padding: 12px 16px; overflow-x: auto; }
pre code { background: none; padding: 0; color: var(--bright); }
.layout { display: flex; max-width: 1280px; margin: 0 auto; align-items: flex-start; }
nav { width: 290px; flex-shrink: 0; padding: 24px 12px 24px 24px;
  border-right: 1px solid var(--border); }
.navtitle { font-weight: 700; color: var(--bright); font-size: 13px;
  letter-spacing: .06em; text-transform: uppercase; margin-bottom: 8px; }
.navgroup { color: var(--muted); font-size: 11px; letter-spacing: .08em;
  text-transform: uppercase; margin: 16px 0 4px; font-weight: 600; }
nav a { display: flex; gap: 8px; align-items: baseline; padding: 3px 8px;
  border-radius: 6px; color: var(--text); font-size: 13px; }
nav a:hover { background: var(--surface); text-decoration: none; }
nav .m { font-family: var(--mono); font-size: 10px; font-weight: 700; width: 44px;
  flex-shrink: 0; text-align: right; }
nav .p { font-family: var(--mono); font-size: 12px; overflow: hidden;
  text-overflow: ellipsis; white-space: nowrap; }
main { flex: 1; min-width: 0; padding: 32px 40px 80px; }
header h1 { color: var(--bright); font-size: 28px; margin: 0 0 4px; }
.meta { color: var(--muted); font-size: 13px; display: flex; gap: 12px;
  flex-wrap: wrap; align-items: center; margin: 0 0 8px; }
.pill { border: 1px solid var(--border); border-radius: 999px; padding: 1px 10px;
  font-size: 12px; color: var(--text); background: var(--surface); }
.pill.v { color: var(--purple); border-color: rgba(168,85,247,.33); }
h2 { color: var(--bright); font-size: 20px; margin: 40px 0 8px;
  padding-top: 24px; border-top: 1px solid var(--border); }
h3 { color: var(--bright); font-size: 16px; margin: 16px 0 8px; }
h4 { color: var(--muted); font-size: 11px; text-transform: uppercase;
  letter-spacing: .08em; margin: 16px 0 6px; }
h4 a { text-transform: none; letter-spacing: normal; }
h4.sub { font-family: var(--mono); text-transform: none; letter-spacing: normal;
  font-size: 12px; color: var(--bright); }
.tagdesc { color: var(--muted); margin-top: 0; }
.intro h2 { font-size: 18px; }
.op { background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px 20px 20px; margin: 16px 0; }
.opline { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.badge { font-family: var(--mono); font-weight: 700; font-size: 12px;
  border: 1px solid; border-radius: 6px; padding: 2px 8px; }
.m-get { color: var(--blue); }
.m-post { color: #22c55e; }
.m-put { color: var(--purple); }
.m-patch { color: #f59e0b; }
.m-delete { color: #ef4444; }
.badge.m-get { background: rgba(14,165,233,.1); border-color: rgba(14,165,233,.33); }
.badge.m-post { background: rgba(34,197,94,.1); border-color: rgba(34,197,94,.33); }
.badge.m-put { background: rgba(168,85,247,.1); border-color: rgba(168,85,247,.33); }
.badge.m-patch { background: rgba(245,158,11,.1); border-color: rgba(245,158,11,.33); }
.badge.m-delete { background: rgba(239,68,68,.1); border-color: rgba(239,68,68,.33); }
.path { background: none; font-size: 14px; padding: 0; }
.scope { margin-left: auto; font-family: var(--mono); font-size: 11px;
  color: var(--purple); border: 1px solid rgba(168,85,247,.2); border-radius: 999px;
  padding: 1px 10px; background: rgba(168,85,247,.05); }
.scope.open { color: var(--muted); border-color: var(--border); background: none; }
.op h3 { margin: 10px 0 4px; }
.opdesc p { margin: 6px 0; }
.tblwrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th { text-align: left; color: var(--muted); font-weight: 600; font-size: 12px;
  padding: 6px 12px 6px 0; border-bottom: 1px solid var(--border); }
td { padding: 7px 12px 7px 0; border-bottom: 1px solid var(--border);
  vertical-align: top; }
tr:last-child td { border-bottom: none; }
td.type { font-family: var(--mono); font-size: 12px; color: var(--text); }
td.muted { color: var(--muted); }
.fmt { color: var(--muted); font-size: 11px; }
.req { color: var(--purple); font-size: 10.5px; font-family: var(--mono); }
.code { font-family: var(--mono); font-weight: 700; font-size: 12.5px; }
.code.ok { color: #22c55e; }
.code.err { color: var(--muted); }
.schema h3 { font-family: var(--mono); }
footer { margin-top: 48px; }
@media (max-width: 900px) {
  .layout { flex-direction: column; }
  nav { width: 100%; border-right: none; border-bottom: 1px solid var(--border); }
  main { padding: 24px 16px 60px; }
}
`
