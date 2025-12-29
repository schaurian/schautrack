# Schautrack

Calorie tracking web app with authentication, TOTP-based 2FA, daily goals, and a day-by-day overview. Runs in Docker with Postgres.

## Features
- Email + password auth with optional TOTP 2FA (QR setup + disable flow)
- Manage daily calorie goal and 2FA from a single Settings page
- Log calories as positive (consumed) or negative (burned), with custom dates
- Dashboard shows today's progress and a 14-day goal hit/miss overview
- AI-powered calorie estimation from food photos (OpenAI or Claude)
- Postgres-backed sessions and data
- Dockerized app + database
- GitLab CI builds Docker images and pushes to the project registry
- Android WebView wrapper (loads https://schautrack.schauer.to) in `android/`

## Quickstart (Docker)
1) Copy env template and adjust secrets as needed:
```
cp .env.example .env
```
2) Build and run:
```
docker compose up --build
```
3) App is available at http://localhost:3000

## Local development (without Docker)
You’ll need Node 18+ and Postgres. Then:
```
cp .env.example .env        # point DATABASE_URL at your Postgres
npm install
npm run dev                 # or npm start
```

Create the tables using `db/init.sql` or let Docker Compose apply it automatically. The session store uses the `session` table from that script.

- `COOKIE_SECURE=false` keeps cookies usable on plain HTTP (Docker/dev). Set to `true` only when serving over HTTPS.

## CI versioning & tagging
- The GitLab pipeline bumps SemVer on the default branch using Conventional Commits, tags the repo, and pushes container images.
- To allow tag pushes, set CI/CD variables (keep them masked/protected):
  - `GIT_PUSH_TOKEN`: Personal Access Token with `write_repository` (or `api`) scope.
  - `GIT_PUSH_USER` (optional): Username for the token; defaults to `gitlab-ci-token`. Use your PAT username if preferred.
- Without these variables the semver job cannot push tags and will fail.
- Tagging rules:
  - Default branch builds: `latest`, SemVer (e.g., `v1.2.31`), and commit SHA.
  - Other branches: commit SHA + branch slug tag (e.g., a `staging` branch pushes `:staging`).
- Container registry cleanup: add a masked CI variable `REGISTRY_POLICY_TOKEN` (API scope PAT) to let the `registry-expiration-policy` job enforce an expiration policy (keep `latest` and all semver tags, retain 15 tags total, purge anything older than 30 days weekly).
- Deployment is handled via GitOps in a separate Kubernetes repo; this pipeline only builds and pushes images (`latest`, semver tags, and commit SHA/branch tags). Point your GitOps overlays (e.g., Argo CD/Flux) at the desired tags for staging/production.

## Two-factor setup
- Visit `/2fa` after logging in.
- Click "Start setup" to get a QR code / otpauth URL.
- Verify a 6-digit code from your authenticator to activate.
- To disable, confirm with a current code.

## AI Photo Calorie Estimation
Estimate calories from food photos using OpenAI (GPT-4o) or Claude (Sonnet) vision APIs.

### Setup
1. Generate an encryption key for API key storage:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

2. Add to your `.env`:
   ```
   API_KEY_ENCRYPTION_SECRET=<generated-key>
   ```

3. Restart the app to apply the configuration.

4. In the app, go to **Settings > AI Features**:
   - Select your preferred AI provider (OpenAI or Claude)
   - Enter your API key (get one from [platform.openai.com](https://platform.openai.com) or [console.anthropic.com](https://console.anthropic.com))
   - Save settings

### Global API Keys (Admin)
Administrators can set global API keys that all users can use:

**Via environment variables:**
```
OPENAI_API_KEY=sk-...
CLAUDE_API_KEY=sk-ant-...
```

**Via admin settings:** Navigate to `/admin` and configure the OpenAI/Claude API keys in the Application Settings section.

Global keys are used as a fallback when users don't have their own keys configured. User-specific keys take priority over global keys.

### Usage
Once configured (either per-user or globally), a camera button appears in the dashboard header:
- Click the button to open the photo modal
- Take a photo (camera access on mobile) or upload an image
- The AI analyzes the food and estimates calories
- Click "Use this estimate" to populate the form, or "Add entry" to submit directly

API keys are encrypted before storage using AES-256-GCM.

## Environment Variables

All variables can be set in `.env` file. Some can also be configured via the `/admin` settings page (env vars always take precedence over DB settings).

### Required

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `SESSION_SECRET` | Session encryption key (change in production!) |
| `SUPPORT_EMAIL` | Contact email shown on support/error pages |

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Port to listen on |
| `COOKIE_SECURE` | `false` | Set to `true` when serving over HTTPS |

### Admin

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_EMAIL` | *(empty)* | Email that gets access to `/admin` page |

### Legal Pages

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_LEGAL` | `false` | Set to `true` to enable `/imprint`, `/privacy`, `/terms` |
| `IMPRINT_NAME` | `Operator` | Operator name on imprint page |
| `IMPRINT_URL` | `/imprint` | URL for imprint link |
| `IMPRINT_ADDRESS` | *(empty)* | Physical address (use `\n` for line breaks) |
| `IMPRINT_EMAIL` | *(empty)* | Contact email (rendered as SVG for spam protection) |

### SMTP (Password Reset)

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | *(empty)* | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | *(empty)* | SMTP username |
| `SMTP_PASS` | *(empty)* | SMTP password |
| `SMTP_FROM` | `SUPPORT_EMAIL` | From address for emails |
| `SMTP_SECURE` | `false` | Set to `true` for SSL/TLS |

### AI Features

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY_ENCRYPTION_SECRET` | *(empty)* | AES-256-GCM key for encrypting user API keys |
| `OPENAI_API_KEY` | *(empty)* | Global OpenAI API key (fallback for all users) |
| `CLAUDE_API_KEY` | *(empty)* | Global Claude API key (fallback for all users) |

### Build

| Variable | Default | Description |
|----------|---------|-------------|
| `BUILD_VERSION` | *(empty)* | Version shown in footer (set by CI) |

## Project layout
- `src/server.js` – Express server, routes, auth + 2FA, dashboard logic
- `src/views/` – EJS templates for auth, dashboard, 2FA
- `src/public/` – Stylesheet
- `db/init.sql` – Database schema (users, entries, session store)
- `docker-compose.yml` – App + Postgres stack
