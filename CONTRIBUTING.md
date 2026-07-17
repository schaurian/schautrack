# Contributing to Schautrack

Thanks for your interest in contributing!

## Branch Workflow

This project integrates through `staging`, not `main`:

1. Fork the repository (or, if you have push access, create a topic branch).
2. Create a feature branch from `staging` (e.g. `fix-entry-validation`).
3. Make your changes and commit them.
4. Open a **pull request against `staging`**.

`staging` is the integration branch: it builds a `staging-*` container image and
publishes the Helm chart to the staging channel. Releases flow from `staging` to
`main` — merging to `main` auto-computes a semver tag, publishes the stable Helm
chart, and creates a GitHub Release. Do **not** target `main` directly with
feature PRs.

Use [Conventional Commits](https://www.conventionalcommits.org/) prefixes
(`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, …) — CI derives the release
version from them.

## Development Setup

Prerequisites: Docker + Docker Compose, Go (version pinned in `go.mod`), and
Node.js + npm (for the client build and the end-to-end suite).

Run the app locally with the dev compose stack (app + PostgreSQL):

```bash
docker compose -f compose.dev.yml up -d --build
```

The web app is then available at http://localhost:3000. Environment variables
are read from a local `.env` file — copy `.env.example` to `.env` and adjust as
needed.

The React client lives in `client/`. To iterate on the frontend with hot reload:

```bash
cd client
npm install
npm run dev      # Vite dev server
npm run build    # type-check (tsc -b) + production build
```

## Running Tests

**Go backend** — unit/integration tests run with the standard toolchain (this is
the same `test` job that gates CI):

```bash
go test ./...
```

**End-to-end (Playwright)** — the root `package.json` is a thin test harness. Its
`test:e2e` script builds and starts the full stack defined in `compose.test.yml`
(app on port 3001, PostgreSQL, Mailpit), seeds a test user, then runs the
Playwright suite in `e2e/`:

```bash
npm install                       # installs @playwright/test + tsx (root deps)
npx playwright install chromium   # one-time: download the browser
npm run test:e2e
```

Related scripts:

- `npm run test:e2e:ui` — run the suite with the Playwright UI.
- `npm run test:e2e:setup` — bring the test stack up and seed the user, then
  leave it running (useful for iterating on individual specs).
- `npm run test:e2e:down` — tear the test stack down and remove its volumes.

Please add or update tests for any behavior you change, and run both `go test
./...` and the e2e suite before opening a pull request.

## Copyright Assignment

By submitting a contribution to this project, you agree to assign the copyright of your contribution to the project owner. This allows the project to be relicensed under different terms in the future if needed (including permissive or commercial licenses).

If you do not agree to these terms, please do not submit contributions.
