# API reference page (`GET /api/v1/docs`) — design

**Date:** 2026-08-08
**Status:** approved (mockup reviewed in browser, generated from the live spec)

## Problem

The "View the API reference." link in Settings → API tokens points at
`/api/v1/openapi.json` — a raw JSON dump. That is the machine-readable
artifact, not something a person can read.

## Decision

Serve a human-readable API reference at **`GET /api/v1/docs`**: one
self-contained HTML page, rendered server-side from the same typed
`openapi.Document` the instance already serves. No JavaScript, inline CSS
only — it passes the app's CSP (`script-src 'self'`, `style-src 'self'
'unsafe-inline'`) untouched. The Settings link keeps its text and locale
strings and changes only its `href` to `/api/v1/docs`.

Rejected alternatives:

- **Vendored Swagger UI / Scalar / Redoc** — megabytes of third-party JS in
  the image to work around the CSP, plus an asset to keep updated. The
  existing `Markdown()` design comment already rejects this trade; the served
  `openapi.json` remains the artifact to point interactive tools at.
- **Linking to `docs/api-v1.md` on GitHub** — a self-hosted instance would
  link to upstream's `main`, a possibly different version than it runs.
- **A route in the SPA** — needs a markdown renderer dependency and ships a
  second copy of content the server already has.

## Architecture

```
internal/openapi/html.go      (d *Document) HTML() string — sibling of Markdown()
internal/handler/v1_openapi.go V1Handler.Docs — serves the page, cached like .spec
internal/handler/v1_router.go r.Get("/docs", h.Docs) next to /openapi.json, outside auth
internal/openapi/spec.go      spec entry for GET /docs (tag Meta, no auth, text/html)
client ApiTokenSettings.tsx   href /api/v1/openapi.json → /api/v1/docs
```

### The generator (`html.go`)

Walks the same typed values as `Markdown()`. Page structure, top to bottom:

1. **Header** — title, pills for contract version, OpenAPI version, and the
   `servers[0]` URL, plus a link to `openapi.json`. Info summary underneath.
2. **Prose** — `Info.Description` (authentication, scopes, errors, dates,
   pagination, idempotency) rendered by the markdown-subset converter below.
3. **Endpoint sections** grouped by tag, in the document's tag order, each
   operation a card: color-coded method badge, monospace path, scope chip
   (from the operation's security requirement; "token, any scope" when a
   token is needed but no scope; "no auth" for the open endpoints), summary,
   description, then Parameters / Request body / Responses tables. Response
   rows link `$ref` bodies to the schema section.
4. **Schema reference** — every component schema as a field table (name,
   type with format/enum, required marker, description). `$ref` types link
   to their anchors.
5. **Footer** — "One day at a time · Schautrack API reference" + spec link.

Anchors: operations `#<method>-<path-with-dashes>` (e.g. `#post-entries`),
schemas `#schema-<Name>`, so the page is deep-linkable.

A left **nav column** lists every operation (method + path) grouped by tag,
plus a Schemas link. It is **not sticky**: the sticky variant
(`position: sticky` + own scroll) repeatedly froze Chrome's renderer during
mockup review; the approved mockup scrolls the nav with the page. Sticky may
be revisited later, verified in real browsers first.

### Markdown-subset converter

`Info.Description` and operation descriptions use a constrained subset, and
the converter handles exactly that subset: `##`–`####` headings, paragraphs,
fenced code blocks, `-` bullet lists, `|` tables, and inline `` `code` ``,
`**bold**`, `*italic*`, `[text](url)`. Everything is HTML-escaped before
inline markup is applied. A test asserts no literal markdown artifacts
(`**`, `## `, `` ``` ``) survive in the rendered page, so a new construct in
the spec prose fails the build instead of rendering raw.

### Handler and caching

Same pattern as `V1Handler.OpenAPI`: a `sync.Once`-guarded field on the
handler builds `openapi.Build(h.BuildVersion, h.BaseURL).HTML()` on first
request. Per-handler, not process-wide, for the same reason as the spec
(invariant #8): nothing request-derived enters the document, and one
instance's `BASE_URL` cannot be served by another. Response:
`Content-Type: text/html; charset=utf-8`.

### Spec entry

`GET /docs` is added to `internal/openapi/spec.go` — tag Meta, explicit
empty security requirement (like `/openapi.json`), one `200` response with
content type `text/html`. This keeps `TestV1RoutesMatchSpec` green and makes
the page discoverable from the spec itself. `api/openapi.json` and
`docs/api-v1.md` are regenerated via `go run ./cmd/apidocs`.

## Visual design

Approved via mockup (generated from the live dev spec, all 18 endpoints and
42 schemas). Flat material, dark-only, app palette:

- Background `#070d1a`, cards `#0a1220`, code/pre `#0d1526`,
  border `rgba(255,255,255,.08)`
- Text `#c3ccdd`, headings `#e8ecf4`, muted `#7d8aa0`
- Accents: blue `#0ea5e9`, purple `#a855f7` (scope chips, version pill)
- Method badges: GET blue `#0ea5e9`, POST green `#22c55e`, PATCH amber
  `#f59e0b`, PUT purple `#a855f7`, DELETE red `#ef4444` — tinted flat
  backgrounds, no gradients or glows
- System font stack; `ui-monospace` stack for paths, fields, and code
- Tables scroll horizontally inside their own wrapper; the page body never
  scrolls horizontally. Below 900px the nav collapses above the content.

## Not in scope

- No "Try it out" console — `openapi.json` remains the artifact for
  interactive tools (Scalar, Bruno, Insomnia, generators).
- No light theme, no JS enhancements (search, collapse), no i18n of the page
  (the spec prose is English; the generated `docs/api-v1.md` is too).
- The v1 404 problem-detail text keeps pointing at `openapi.json` (its
  audience is API clients, not people).

## Testing

- **`internal/openapi`**: `HTML()` contains every operation's method+path
  anchor and every schema anchor; escapes HTML in descriptions; no raw
  markdown artifacts; italic/bold/code/link inline rendering covered by
  table-driven converter tests.
- **`internal/handler`**: `GET /api/v1/docs` returns 200 `text/html` with no
  Authorization header; the body is byte-identical across two requests
  (cache); route/spec parity via the existing `TestV1RoutesMatchSpec`.
- **Generated artifacts**: existing staleness test fails if
  `api/openapi.json` / `docs/api-v1.md` aren't regenerated.
- **Client**: existing e2e settings flow still passes; the link now points
  at `/api/v1/docs`.

## Documentation updates

- README: add `GET /docs` to the public-API description.
- CLAUDE.md Public API layout: add `internal/openapi/html.go`.
- Update the design comment on `Markdown()` — it argues against a bundled JS
  docs page; note that the served `/docs` page is the zero-JS resolution of
  that same argument, not a reversal.
