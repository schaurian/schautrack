# Design: Configurable release source + gated "Report an Issue"

Date: 2026-07-19
Branch: `worktree-report-issue-version-gate` (off `staging`)

## Goal

Add a first-class **"Report an Issue"** control that opens a pre-filled new issue on
the project's issue tracker. Make the **release/issue source configurable** (a
pluggable provider, GitHub or GitLab). When the running instance is **not on the
latest release**, require the user to tick a confirmation checkbox before the report
button enables — reducing duplicate / already-fixed reports without hard-blocking.

## Current state (already in `staging`)

- `internal/handler/version.go` — `LatestVersion(enabled)` fetches the latest release
  from a **hardcoded** GitHub constant (`api.github.com/repos/schaurian/schautrack/releases/latest`),
  caches it (1h TTL, 5m on error), and honours the `UPDATE_CHECK_ENABLED=false` opt-out.
  Response today: `{ "latest": "1.2.3" | null }`.
- `internal/handler/health.go` — `/api/health` returns `{ app, status, version, pool }`.
- `internal/config/config.go` — has `UpdateCheckEnabled` (from `UPDATE_CHECK_ENABLED`).
- `cmd/server/main.go` — wires `GET /api/latest-version` and `GET /api/health`.
- `client/src/components/Layout/Footer.tsx` — fetches `/api/health` + `/api/latest-version`,
  computes `outdated` inline, and **already renders the version in red** (`text-destructive`)
  when outdated. Hardcodes the GitHub repo URL for its icon link.
- `client/src/pages/Settings/Settings.tsx` — has an **unconditional** footer line:
  *"Spotted a bug or missing a feature? Open an issue on GitHub"* → hardcoded
  `https://github.com/schaurian/schautrack/issues`.

## Requirements

1. **Pluggable release source** — provider (`github` | `gitlab`) + repo + optional
   self-hosted base URL, all configurable via env. Drives the update check **and** the
   issue links. Ships with both GitHub and GitLab providers implemented and tested.
2. **Report an Issue = pre-filled new issue** — opens the provider's "new issue" URL
   with title/body pre-filled (app version, browser/OS, current page).
3. **Dedicated Settings card** — a "Report an Issue" card in the Settings grid.
4. **Version shown red when outdated** — keep the existing red treatment; mirror it in
   the new card.
5. **Soft gate when outdated** — if the instance is not on the latest release, a
   **required checkbox** must be ticked before the report button enables. Wording
   (both combined): *"I understand I'm on an older version (vX.Y.Z) and my issue may
   already be reported or fixed — I've checked the open issues and still want to report it."*
   A "Browse open issues" link sits next to it.
6. **Graceful degradation** — if the latest version can't be determined (check disabled,
   provider unreachable, or a dev/staging build), treat as up-to-date: no checkbox,
   report works, version not shown red.

## Design

### 1. Release provider abstraction (backend)

New package `internal/release`:

```go
package release

type Provider interface {
    // LatestReleaseRequest builds the API request for the newest release.
    LatestReleaseRequest(ctx context.Context) (*http.Request, error)
    // ParseLatestTag extracts the normalized tag (leading "v" stripped) from the body.
    ParseLatestTag(body []byte) (string, error)
    // Name is the provider slug exposed to the client ("github" | "gitlab").
    Name() string
    // RepoURL is the human-facing repository URL.
    RepoURL() string
    // IssuesURL is the human-facing open-issues list URL.
    IssuesURL() string
    // NewIssueURLTemplate is the human-facing "new issue" URL containing the literal
    // tokens {title} and {body}; the client substitutes URL-encoded values.
    NewIssueURLTemplate() string
}

func New(provider, repo, baseURL string) (Provider, error) // factory; defaults provider=github
```

Concrete providers:

**GitHub** (`baseURL` default `https://github.com`; API `https://api.github.com`, or
`{base}/api/v3` for GitHub Enterprise when a non-default base is set):
- Latest API: `GET {api}/repos/{owner}/{repo}/releases/latest`, headers
  `Accept: application/vnd.github+json`, `User-Agent: schautrack-server`; parse `.tag_name`.
- Repo: `https://github.com/{owner}/{repo}`
- Issues: `.../issues`
- New issue: `.../issues/new?title={title}&body={body}`

**GitLab** (`baseURL` default `https://gitlab.com`; API `{base}/api/v4`):
- Latest API: `GET {base}/api/v4/projects/{owner%2Frepo}/releases?per_page=1&order_by=released_at&sort=desc`;
  parse first element's `.tag_name` (array response tolerates GitLab versions without
  the `releases/permalink/latest` endpoint).
- Repo: `{base}/{owner}/{repo}`
- Issues: `{base}/{owner}/{repo}/-/issues`
- New issue: `{base}/{owner}/{repo}/-/issues/new?issue[title]={title}&issue[description]={body}`

The provider only builds requests/URLs and parses tags. The existing HTTP client,
cache, TTL, and `UPDATE_CHECK_ENABLED` opt-out stay in the handler, provider-agnostic.

### 2. Config (env vars)

New in `internal/config/config.go` (`Config` fields + `Load()`):

| Env var | Default | Meaning |
|---|---|---|
| `UPDATE_PROVIDER` | `github` | `github` \| `gitlab` |
| `UPDATE_REPO` | `schaurian/schautrack` | `owner/repo` (or `group/subgroup/project` for GitLab) |
| `UPDATE_BASE_URL` | provider default | Self-hosted host, e.g. `https://gitlab.example.com` |
| `UPDATE_CHECK_ENABLED` | `true` (existing) | `false` disables the outbound release check |

Unknown `UPDATE_PROVIDER` → `release.New` returns an error; `main.go` logs it and falls
back to the GitHub default (never fatal — a bad value must not break startup).

### 3. `/api/latest-version` response (extended)

```json
{
  "latest": "1.2.3",            // or null when disabled/unreachable
  "provider": "github",
  "repoUrl": "https://github.com/schaurian/schautrack",
  "issuesUrl": "https://github.com/schaurian/schautrack/issues",
  "newIssueUrlTemplate": "https://github.com/schaurian/schautrack/issues/new?title={title}&body={body}"
}
```

The URL fields come from static config and are **always present** (so reporting works
even with `UPDATE_CHECK_ENABLED=false`); only `latest` is gated by the check. `main.go`
builds the provider once at startup and passes it to `handler.LatestVersion`.

### 4. Frontend: shared version hook

Extract the version comparison into `client/src/lib/version.ts`:
- `isOutdated(current, latest): boolean` (moved out of `Footer.tsx`)
- types for the `/api/latest-version` payload.

New hook `client/src/hooks/useVersionInfo.ts`:
- fetches `/api/health` (current) + `/api/latest-version` (latest + URLs),
- computes `outdated` (skipping `dev` / `staging*` builds, as Footer does today),
- returns `{ current, latest, outdated, provider, repoUrl, issuesUrl, newIssueUrlTemplate, loading }`.
- `Footer.tsx` is refactored to consume the hook (its GitHub link now uses `repoUrl`).

### 5. Frontend: "Report an Issue" card

New `client/src/pages/Settings/ReportIssueCard.tsx`, rendered in the Settings grid;
consumes `useVersionInfo()`.

- Header "Report an Issue"; shows current version, **red when `outdated`**.
- Pre-filled body (client-built, markdown):
  ```
  **Version:** v1.2.3
  **Browser:** <navigator.userAgent>
  **Page:** <location.href>

  **Describe the issue:**

  **Steps to reproduce:**
  ```
  Title left empty for the user. The report link/button is
  `newIssueUrlTemplate` with `{title}`→"" and `{body}`→`encodeURIComponent(body)`,
  opened in a new tab (`rel="noopener noreferrer"`).
- **Up-to-date** (or undeterminable): button enabled directly.
- **Outdated**: shows "vLATEST available", a "Browse open issues" link (`issuesUrl`),
  and the required checkbox (wording above). Button `disabled` until checked.
- Remove the old unconditional "Open an issue on GitHub" line from `Settings.tsx`.

### 6. Tests

**Go (`internal/release/provider_test.go`, `internal/handler/version_test.go`):**
- `release.New` returns the right provider; unknown provider errors.
- GitHub + GitLab: `RepoURL`, `IssuesURL`, `NewIssueURLTemplate` string construction
  (incl. GitLab `owner%2Frepo` encoding and self-hosted base).
- `ParseLatestTag` for each provider (GitHub object, GitLab array; `v`-prefix stripped).
- Handler: latest-version response includes URL fields when disabled (no phone-home)
  and the tag when enabled (against an `httptest` API server). Keep the existing
  `TestLatestVersionDisabled_NoPhoneHome`.

**Client (vitest):**
- `lib/version.ts` `isOutdated` truth table.
- `ReportIssueCard`: checkbox required ⇔ outdated; button enabled/disabled accordingly;
  built new-issue URL contains the version and encoded body.
- (If vitest isn't wired in `client/` yet, add the dev dep + minimal config as part of
  this work; `client/package.json` already declares a `test: vitest run` script.)

## Files touched

- `internal/release/provider.go` (new), `internal/release/provider_test.go` (new)
- `internal/config/config.go` (add 3 fields + parsing)
- `internal/handler/version.go` (use provider; extend response)
- `internal/handler/version_test.go` (extend)
- `cmd/server/main.go` (build provider, pass to handler)
- `client/src/lib/version.ts` (new), `client/src/hooks/useVersionInfo.ts` (new)
- `client/src/components/Layout/Footer.tsx` (consume hook)
- `client/src/pages/Settings/ReportIssueCard.tsx` (new)
- `client/src/pages/Settings/Settings.tsx` (render card; remove old link)
- client tests (new); `.env.example` (document the 3 new env vars)

## Non-goals / out of scope

- No in-app issue submission (we open the provider's web new-issue form; no API token,
  no server-side issue creation).
- No providers beyond GitHub + GitLab (interface leaves room for more).
- No change to how `BUILD_VERSION` is produced by CI.
- No auth/rate-limit changes.
```