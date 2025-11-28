# Schautrack

Calorie tracking web app with authentication, TOTP-based 2FA, daily goals, and a day-by-day overview. Runs in Docker with Postgres.

## Features
- Email + password auth with optional TOTP 2FA (QR setup + disable flow)
- Manage daily calorie goal and 2FA from a single Settings page
- Log calories as positive (consumed) or negative (burned), with custom dates
- Dashboard shows today’s progress and a 14-day goal hit/miss overview
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

## Two-factor setup
- Visit `/2fa` after logging in.
- Click “Start setup” to get a QR code / otpauth URL.
- Verify a 6-digit code from your authenticator to activate.
- To disable, confirm with a current code.

## Project layout
- `src/server.js` – Express server, routes, auth + 2FA, dashboard logic
- `views/` – EJS templates for auth, dashboard, 2FA
- `public/` – Stylesheet
- `db/init.sql` – Database schema (users, entries, session store)
- `docker-compose.yml` – App + Postgres stack
