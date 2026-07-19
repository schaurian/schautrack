# Claude Code Context

This document contains important context and decisions for Claude Code when working on this project.

## Project Overview

**Schautrack** is a calorie tracking web application built with Go (chi router) and PostgreSQL. It supports:
- User authentication with optional 2FA (TOTP) and backup codes
- Passkeys / WebAuthn — passwordless login and step-up (`handler/passkeys.go`, `service/passkeys.go`, enabled via `PASSKEYS_RP_ID`)
- OIDC / OpenID Connect SSO — single external provider, invite-aware, with brand logo detection (`handler/oidc.go`, `service/oidc.go`, enabled via `OIDC_ISSUER`)
- Step-up (re-)authentication — a grace-windowed elevation required for sensitive auth-method changes (`handler/stepup.go`, `middleware/stepup`, `STEP_UP_TTL`)
- Email verification and transactional email — registration verification, email-change verification, password reset, and 2FA-reset emails (`handler/auth_email.go`, `service/email.go`; requires SMTP)
- Captcha — SVG challenge on login / registration / verification-resend for brute-force protection (`service/captcha.go`, `GET /auth/captcha`)
- Calorie entry tracking with daily goals
- AI-powered calorie estimation from food photos (OpenAI, Claude, or Ollama)
- Macro (macronutrient) tracking — protein, carbs, fat, fiber, sugar (`service/macros.go`, `POST /settings/macros`)
- Saved foods — reusable quick-add favorites that can be tracked into entries (`handler/saved_foods.go`, `/api/saved-foods`)
- Recurring per-day todos (`handler/todos.go`, `service/todos.go`, `/api/todos`)
- Weight tracking
- Daily notes per date (enableable per user)
- Account data export / import (`handler/entries_export.go`, `POST /settings/export`)
- Account linking to share data with other users
- Timezone-aware entry timestamps
- Real-time updates via Server-Sent Events (SSE)
- Invite-only registration mode (configurable via env var or admin panel)

## Project Structure

```
schautrack/
├── client/                # React 19 SPA (Vite + TypeScript)
│   ├── src/
│   │   ├── api/           # API client layer (fetch wrappers)
│   │   ├── components/    # Shared components (Layout, ui)
│   │   ├── pages/         # Page components (Dashboard, Settings, etc.)
│   │   ├── hooks/         # Custom hooks (useAuth, useSSE)
│   │   ├── stores/        # Zustand stores (auth, dashboard)
│   │   ├── types/         # TypeScript types
│   │   ├── lib/           # Shared utilities (macros, mathParser)
│   │   ├── styles/        # CSS variables and global styles
│   │   ├── App.tsx
│   │   ├── router.tsx
│   │   └── main.tsx
│   ├── package.json
│   ├── vite.config.ts
│   └── tsconfig.json
├── cmd/server/            # Go entry point
│   └── main.go            # Server startup, routing, graceful shutdown
├── internal/              # Go backend (JSON API only)
│   ├── config/            # Environment variable parsing
│   ├── database/          # Pool, migrations, settings cache
│   ├── model/             # Data models (User, Entry, etc.)
│   ├── session/           # PostgreSQL session store, CSRF, step-up TTL
│   ├── middleware/         # Auth, rate limiting, security headers, timezone, step-up
│   ├── clientip/          # Client IP extraction (proxy-aware)
│   ├── handler/           # HTTP handlers (auth, entries, settings, etc.)
│   ├── service/           # Business logic (macros, math parser, AI, email, etc.)
│   └── sse/               # Server-Sent Events broker
├── e2e/                   # Playwright end-to-end specs (run via root package.json)
├── helm/schautrack/       # Helm chart (Kubernetes deployment)
├── docs/                  # Manual test checklist + screenshots
├── scripts/               # Build helpers (bump-version.sh, generate-changelog.sh)
├── public/                # Static assets (logo, favicons)
├── db/
│   └── init.sql           # Intentionally empty — schema comes from Go migrations
├── Dockerfile             # 3-stage build (client, Go binary, Alpine)
├── compose.yml            # Production Docker Compose
├── compose.dev.yml        # Local development setup
├── compose.test.yml       # E2E test harness (app + DB, CAPTCHA_BYPASS enabled)
├── package.json           # Root — Playwright test:e2e scripts only
├── go.mod
└── go.sum
```

## Technology Stack

### Frontend
- **Framework:** React 19 + TypeScript
- **Build:** Vite 6
- **Routing:** React Router v7
- **Data Fetching:** TanStack Query v5
- **State:** Zustand v5
- **Styling:** CSS Modules with CSS custom properties

### Backend
- **Language:** Go 1.26
- **Router:** go-chi/chi v5 (stdlib-compatible)
- **Database:** PostgreSQL 18 via jackc/pgx v5
- **Session Store:** Custom PostgreSQL store (internal/session)
- **Authentication:** alexedwards/argon2id + golang.org/x/crypto/bcrypt + pquerna/otp (TOTP) + go-webauthn/webauthn (passkeys) + coreos/go-oidc (OIDC SSO)
- **Real-time:** Server-Sent Events (SSE) via internal/sse broker
- **API:** JSON-only (no server-side rendering)
- **Docker image:** ~21MB (Alpine + static Go binary)

## Design Decisions

### Color Scheme
- **Background:** Dark blue-purple gradient with blue (#0ea5e9) and purple (#a855f7) accents
- **Base colors:** Very dark blue (#070d1a, #0a1220)
- **Cards:** Dark with subtle borders
- Changed from orange/yellow to purple accents (user preference)

### UI/UX
- Removed eyebrow labels ("Today", "Log", "Recent") for cleaner look
- Footer always sticks to bottom (flexbox layout)
- Dot rows in share cards have 16px top/bottom margin, 36px row-gap for wrapping
- Dots use `justify-content: space-between` with 8px left/right padding in share cards
- 8px column gap between dots for tighter spacing

### Timezone Handling
- Each user has their own timezone stored in the database
- Your own entry timestamps display in your timezone
- Timezone is auto-detected from client and persisted to DB
- When viewing linked user's entries, entry times show in the CREATOR's timezone (so you see when they actually ate, not what time it was for you)

### Docker Optimization
- 3-stage build: Node (client), Go (binary), Alpine (final ~21MB)
- Go handles signals natively (no dumb-init needed)
- CGO_ENABLED=0 for fully static binary
- Runs as non-root `appuser`

### Kubernetes / Health Checks
- **Health endpoint:** `GET /api/health` - checks database connectivity, returns 200 with app info or 503 on failure
- **Liveness probe:** Use HTTP GET to `/api/health` - restarts container if app is unresponsive
- **Readiness probe:** Use HTTP GET to `/api/health` - removes pod from service if DB connection fails
- **Deployment strategy:** RollingUpdate with `maxUnavailable: 0` ensures zero-downtime deployments (old pod stays until new pod is ready)
- **Helm chart:** Includes probes and strategy by default

## CI/CD Pipeline

### GitHub Actions
- **Workflow:** `.github/workflows/build.yml`
- **Registry:** GitHub Container Registry (ghcr.io)
- **Architectures:** linux/amd64, linux/arm64

### Automatic Versioning (Conventional Commits)
The CI automatically computes semantic versions based on commit message prefixes:
- `breaking:` or `major:` → **Major** bump (X.0.0)
- `feat:` or `feature:` or `minor:` → **Minor** bump (x.Y.0)
- `fix:` or `patch:` or `chore:` or `docs:` or `refactor:` → **Patch** bump (x.y.Z)
- No recognized prefix → defaults to **Patch** bump

**Important:** Tags are created automatically by CI on main branch - do NOT create version tags manually.

### Branch Behavior
- `main`: Auto-creates semver tag (vX.Y.Z), builds container with version + `latest` tags, creates GitHub Release, publishes Helm chart to stable channel
- `staging`: Builds with `staging-{run_number}` tag, publishes Helm chart to staging channel
- Other branches/PRs: Builds with commit SHA only

### Jobs
1. `test`: Runs `go test ./...` (gates the pipeline)
2. `compute-version`: Analyzes commits and calculates next version
3. `create-tag`: Creates git tag on main (automatic)
4. `build-and-push`: Builds multi-arch container images
5. `create-manifest`: Creates multi-arch manifest
6. `create-release`: Creates GitHub Release with changelog
7. `publish-helm`: Publishes Helm chart to gh-pages

## Database Schema Notes

**Schema migrations are handled in code** via `ensureXxxSchema()` functions in `internal/database/migrations.go` - no separate migration scripts or Kubernetes Jobs needed.

### Key Tables
- `users`: User accounts with timezone, daily_goal, weight_unit, TOTP settings
- `calorie_entries`: Date-based entries with amounts and optional names
- `weight_entries`: Date-based weight tracking (unique per user per date)
- `account_links`: Links between users for data sharing (status: pending/accepted/declined)
- `sessions`: PostgreSQL-backed session store

### Account Linking
- Maximum 3 linked accounts per user (`MAX_LINKS = 3`)
- Bidirectional: if A links to B, B links to A
- Links can have custom labels
- Shared data is read-only (no editing other users' entries)

### AI Providers
- **Unified configuration:** Single `ai_key` and `ai_endpoint` fields work for all providers
- **Supported providers:**
  - **OpenAI:** GPT-4o-mini via `https://api.openai.com/v1` (default)
  - **Claude:** Sonnet 4.5 via `https://api.anthropic.com/v1`
  - **Ollama:** Local/self-hosted via `http://localhost:11434/v1` (API key optional)
- **Key precedence** (`resolveAIConfig` in `internal/handler/ai.go`) — the **global key takes precedence over the user's personal key**, not the other way around:
  1. **Global admin key** — used whenever it is set, and it also pins the endpoint and model to the global config. Source order: the `AI_KEY` environment variable overrides the admin-panel `ai_key` setting (`GetEffectiveSetting` in `internal/database/settings.go` treats env as the override and the DB setting as the fallback).
  2. **User personal API key** (encrypted in database) — only honored when **no global key** is configured; the personal key isn't even decrypted otherwise. In that case the global endpoint still applies and the model prefers the user's, falling back to the global one.
- **Custom endpoints:** Users can override default API endpoints for proxies or self-hosted deployments
- **Rate limiting:** Global API key usage can be capped per user per day (configurable via `AI_DAILY_LIMIT`; unlimited by default)

## Environment Variables

> Canonical, exhaustive table with all defaults lives in `README.md`. `internal/config/config.go` is the source of truth for what the process reads; a few knobs (`ENABLE_LEGAL`, `STEP_UP_TTL`, `CAPTCHA_BYPASS`) are read outside the config package and are noted below.

Required:
- `DATABASE_URL`: PostgreSQL connection string
- `SESSION_SECRET`: Session encryption key

Server / general:
- `PORT`: Port to listen on (default: `3000`)
- `ADMIN_EMAIL`: Email address granted access to the `/admin` page
- `BUILD_VERSION`: Injected during build, displayed in footer (default: `dev`)

SEO:
- `ROBOTS_INDEX`: Set to `true` to allow search-engine indexing (default: noindex)
- `BASE_URL`: Base URL for SEO meta tags and the OIDC redirect fallback (auto-detected from request if unset)

Legal / support:
- `SUPPORT_EMAIL`: Contact email for support pages
- `ENABLE_LEGAL`: Set to `true` to enable the `/imprint`, `/privacy`, `/terms` pages (read via `enable_legal` effective setting in `handler/legal.go`; can also be set via admin panel)
- `IMPRINT_URL`: Custom imprint page URL (default: `/imprint`)
- `IMPRINT_ADDRESS`: Full name and address text (rendered as SVG, use \n for line breaks)
- `IMPRINT_EMAIL`: Email text (rendered as SVG)

Features:
- `ENABLE_BARCODE`: Enable barcode scanning via OpenFoodFacts (default: `true`, set `false` to disable)

Registration:
- `ENABLE_REGISTRATION`: `open` (default, anyone can register) or `false`/`invite` (requires invite code). Can also be set via admin panel.

Security / rate limiting:
- `TRUST_PROXY`: Trust `X-Forwarded-For`/`X-Real-Ip` headers for rate limiting (default: `true`, set `false` for direct-access deployments without a reverse proxy)
- `RATE_LIMIT_AUTH`: Max auth attempts per IP per **15-minute** window on login/register/step-up (default: `10`)
- `RATE_LIMIT_STRICT`: Max attempts per IP per **5-minute** window on the strict limiter (forgot/reset password, 2FA reset, email-change request, AI estimate) (default: `5`)
- `STEP_UP_TTL`: Grace window after fresh primary auth during which sensitive auth-method changes are accepted without re-prompting. Any `time.ParseDuration` value (default: `30m`; read in `internal/session/store.go`)
- `CAPTCHA_BYPASS`: **Test-only** — when `true`, any non-empty captcha answer passes. Set only in the E2E harness (`compose.test.yml`); never in production.

SMTP (transactional email — powers password reset, email verification, email change, and 2FA reset):
- `SMTP_HOST`: SMTP server hostname (SMTP is considered configured when `SMTP_HOST` and `SMTP_FROM` are both set)
- `SMTP_PORT`: SMTP port (default: `587`)
- `SMTP_USER`: SMTP username
- `SMTP_PASS`: SMTP password
- `SMTP_FROM`: From address for emails (required alongside `SMTP_HOST` to enable SMTP; used verbatim by `service/email.go`)
- `SMTP_SECURE`: Set to `true` for implicit SSL/TLS (default: `false` / STARTTLS)

OIDC / SSO (single provider — enabled when `OIDC_ISSUER`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET` are all set):
- `OIDC_ISSUER`: OIDC issuer URL (e.g. `https://accounts.google.com`)
- `OIDC_CLIENT_ID`: OAuth2 client ID
- `OIDC_CLIENT_SECRET`: OAuth2 client secret
- `OIDC_LABEL`: Login button label (default: capitalized brand derived from the issuer host, else `SSO`)
- `OIDC_REQUIRE_INVITE`: Require an invite code for OIDC registration (default: `false` — OIDC bypasses invite-only mode)
- `OIDC_REDIRECT_URL`: OAuth2 callback URL (auto-built as `<BASE_URL>/auth/oidc/callback` when unset)

Passkeys / WebAuthn (enabled when `PASSKEYS_RP_ID` is set):
- `PASSKEYS_RP_ID`: Relying Party ID — your domain (e.g. `schautrack.com`)
- `PASSKEYS_RP_NAME`: Display name shown in passkey dialogs (default: `Schautrack`)
- `PASSKEYS_RP_ORIGINS`: Comma-separated allowed origins for multi-domain setups

AI Configuration (Global Fallbacks):
- `AI_PROVIDER`: Default AI provider (`openai`, `claude`, or `ollama`)
- `AI_KEY`: Global API key (fallback when users don't have their own)
- `AI_KEY_ENCRYPTION_SECRET`: Random 32-byte hex string used to encrypt user API keys in the database
- `AI_ENDPOINT`: Optional custom endpoint override (leave blank to use provider defaults)
- `AI_MODEL`: Optional model override (e.g., `gpt-4o`, `claude-sonnet-4-5-20250929`, `gemma3:12b`)
- `AI_DAILY_LIMIT`: Daily AI request limit per user when using global key (default: unlimited; the Helm chart sets it to 10)

## Development Workflow

### Branch Strategy
**IMPORTANT:** Never commit directly to `main`. Always work in the `staging` branch:
1. Make all changes and commits on the `staging` branch
2. Push to `staging` for testing
3. Once verified, merge `staging` into `main` and push
4. **Always switch back to `staging` after pushing to main**: `git checkout staging`

### Local Development
```bash
docker compose -f compose.dev.yml up -d --build
```
- Web app: http://localhost:3000
- PostgreSQL: localhost:5432
- Database schema is created by the app's startup migrations (`db/init.sql` is intentionally a no-op)
- Go build: `go build ./cmd/server/`
- Tests: `go test ./...`

### Deployment
1. Push to `staging` branch to test on staging environment
2. Once staging is verified, merge to `main`: `git checkout main && git merge staging --no-edit && git push origin main`
3. CI automatically creates semver tags and builds containers
4. Deploy using tagged container images

**IMPORTANT:** Never auto-push to staging or main. The user handles all deployments manually.

## Code Patterns

### Timezone Usage
```go
// Get viewer's timezone (for your own entries)
tz := getUserTimezone(r, user) // checks user.Timezone, then X-Timezone header/cookie

// Format timestamps in viewer's timezone (own entries)
timeStr := service.FormatTimeInTz(entry.CreatedAt, tz)

// For linked users, entry times show in the CREATOR's timezone
displayTz := targetUser.Timezone // or "UTC" if nil
```

### SSE for Real-time Updates
- Endpoint: `/events/entries`
- In-memory broker in `internal/sse/broker.go` manages per-user channels
- Sends updates when entries are added/modified/deleted
- Client reconnects automatically on disconnect
- Used for keeping linked user views in sync

## Common Tasks

### Adding a New Feature
1. Schema changes go in `internal/database/migrations.go` only (`db/init.sql` is intentionally empty — migrations are the single source of truth)
2. Add migration in `internal/database/migrations.go`
3. Add service logic in `internal/service/`
4. Add HTTP handler in `internal/handler/`
5. Wire route in `cmd/server/main.go`
6. Create/update React components in `client/src/`
7. **Write tests** for any new or changed logic (see Testing below)
8. Test locally with `docker compose up -d --build`
9. Push to staging for integration testing
10. Merge to main when ready

### Testing
**Always write tests** when adding or changing functionality. Tests use Go's standard `testing` package and run with `go test ./...`.

- **Pure functions** (utils, parsers, validators): Table-driven unit tests in `*_test.go` files alongside the code
- **Session/CSRF**: Test with `httptest.NewRequest` and mock sessions
- **Handlers**: Use `httptest.NewRecorder` + chi router
- **Run tests before committing** — `go test ./...`
- **CI runs tests too** — the `test` job in GitHub Actions gates the build pipeline

### Styling Guidelines
- Use existing CSS variables for colors
- Mobile-first responsive design with `@media (max-width: 768px)`
- Consistent spacing scale: `--space-xs` (4px), `--space-sm` (8px), `--space-md` (12px), `--space-lg` (16px), `--space-xl` (24px)
- Dark theme with subtle gradients and glows

## Performance Considerations

- Database queries use parameterized statements via pgx (SQL injection prevention)
- Session store in PostgreSQL with in-memory prune loop
- Settings cache with 1-minute TTL (`internal/database/settings.go`)
- Static assets served with Go's `http.FileServer`
- Efficient SQL indexes on foreign keys and lookup columns
- 3-stage Docker build: ~21MB final image (vs 171MB with Node)

## Security Notes

- TOTP 2FA implementation using `pquerna/otp`
- Passwords hashed with argon2id (legacy bcrypt supported for migration)
- Session cookies: httpOnly, secure (auto from X-Forwarded-Proto), sameSite: lax
- CSRF protection via session-stored token + constant-time comparison
- Input validation on all user-submitted data
- Runs as non-root user in container
- Security headers via custom middleware (CSP, HSTS, etc.)

## Things to Remember

1. **Own entries:** use the viewer's timezone for timestamps. **Linked user entries:** use the creator's timezone (shows when they actually ate)
2. **Never** commit `.env` files or secrets
3. **Always** test Docker builds after structural changes
4. **Use** Kaniko for CI builds (not Docker-in-Docker)
5. **Keep** backend code in `cmd/` and `internal/` directories
6. **Maintain** the blue-purple color scheme
7. **Never** auto-push to staging or main - user handles deployments
8. **Never** commit directly to main - always commit to staging first, then merge to main
9. **Footer quote:** "One day at a time"
10. **Always** write tests for new or changed logic
11. **Never** change the calorie input `inputmode` — it must stay `inputmode="tel"` to show the numeric keypad on mobile
12. **Never** use `eval()` or `Function()` in client-side code — CSP blocks `unsafe-eval`. Use safe parsers instead
13. **Run** `go test ./...` before committing Go changes
14. **Session cookie** is `schautrack.sid`
