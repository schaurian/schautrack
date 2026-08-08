# API Reference Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve a human-readable, zero-JS HTML API reference at `GET /api/v1/docs`, and point the Settings "View the API reference." link at it.

**Architecture:** A `(d *Document) HTML() string` generator in `internal/openapi` — sibling of `Markdown()`, walking the same typed document — plus a cached public handler wired next to `/openapi.json`. Spec: `docs/superpowers/specs/2026-08-08-api-docs-page-design.md` (approved, with browser-reviewed mockup).

**Tech Stack:** Go stdlib only (`strings`, `regexp`, `html`), no new dependencies. Inline CSS, no JS (CSP: `script-src 'self'`, `style-src 'unsafe-inline'`).

## Global Constraints

- Zero JavaScript in the page; all CSS inline in one `<style>` block.
- Palette: bg `#070d1a`, cards `#0a1220`, code `#0d1526`, border `rgba(255,255,255,.08)`, text `#c3ccdd`, headings `#e8ecf4`, muted `#7d8aa0`, blue `#0ea5e9`, purple `#a855f7`. Method colors: GET `#0ea5e9`, POST `#22c55e`, PATCH `#f59e0b`, PUT `#a855f7`, DELETE `#ef4444`. Flat — no gradients, no glows.
- Nav column is NOT sticky (Chrome renderer freeze found during mockup review).
- Everything user-visible from the spec is HTML-escaped before inline markup is applied.
- Invariants: route/spec parity (`TestV1RoutesMatchSpec`), regenerated artifacts (`go run ./cmd/apidocs`), per-handler caching (no request-derived data in the page).

---

### Task 1: Markdown-subset converter

**Files:**
- Create: `internal/openapi/html_markdown.go`
- Test: `internal/openapi/html_markdown_test.go`

**Interfaces:**
- Produces: `renderProse(md string) string` — block-level: `##`–`####` headings (with `anchor()` ids), fenced code, `- ` lists, `|` tables, paragraphs. `renderInline(s string) string` — escape, then `` `code` ``, `**bold**`, `*italic*`, `[text](url)`.

Steps: table-driven tests first (headings, fence, list, table, bold, italic, code, link, script-tag escaping, `---` separators dropped); run to fail; implement; pass; commit.

### Task 2: HTML page generator

**Files:**
- Create: `internal/openapi/html.go`
- Test: `internal/openapi/html_test.go`

**Interfaces:**
- Consumes: `byTag()`, `anchor()`, `bodySchemaName()`, `renderProse()`, `renderInline()`.
- Produces: `(d *Document) HTML() string` — full standalone page; `opAnchor(method, path) string` (`post-entries` style); `htmlTypeName(s *Schema) string`; field tables recurse into inline objects like `writeFieldTable` (#393).

Page: header (title, version/OpenAPI/server pills, openapi.json link) → prose (`Info.Description`) → non-sticky nav grouped by tag → per-tag op cards (method badge, path, scope chip, summary, description, parameters/request-body/responses tables, `$ref`s linked to `#schema-<Name>`) → schema reference → footer ("One day at a time").

Tests: every operation anchor and schema anchor present; scope chip text for scoped/token-only/public ops; no raw markdown artifacts (`**`, "## ", "```"); HTML-escaped description survives; deterministic output.

### Task 3: Endpoint `GET /api/v1/docs`

**Files:**
- Modify: `internal/openapi/spec.go` (paths map: `/docs` entry modeled on `/openapi.json`; `apiDescription`: "except `/openapi.json`" → "except `/openapi.json` and `/docs`")
- Modify: `internal/handler/v1_openapi.go` (docs cache + `Docs` handler, `text/html; charset=utf-8`)
- Modify: `internal/handler/v1_router.go` (`r.Get("/docs", h.Docs)` beside `/openapi.json`)
- Test: `internal/handler/v1_spec_test.go` pattern — new `v1_docs_test.go`: 200 + content type + no auth + cache stability
- Regenerate: `go run ./cmd/apidocs` (parity + staleness tests gate this)

Spec entry: tag Meta, `Security: []SecurityRequirement{{}}`, single 200 response with `text/html` content (`&Schema{Type: "string"}`).

### Task 4: Settings link

**Files:**
- Modify: `client/src/pages/Settings/ApiTokenSettings.tsx` (href `/api/v1/openapi.json` → `/api/v1/docs`)

No i18n changes — link text stays `apiTokens.specLink`.

### Task 5: Documentation

**Files:**
- Modify: `README.md` (mention `GET /api/v1/docs`), `CLAUDE.md` (layout: `internal/openapi/html.go`), `internal/openapi/markdown.go` (update the anti-bundled-JS design comment to note the zero-JS `/docs` page)

### Task 6: End-to-end verification

- `go test ./...` green; `go vet ./...` clean.
- Run the real server against the dev Postgres, fetch `/api/v1/docs`, verify 200 text/html and render in browser.
- Merge worktree branch into staging (no push).
