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

## Two-factor setup
- Visit `/2fa` after logging in.
- Click “Start setup” to get a QR code / otpauth URL.
- Verify a 6-digit code from your authenticator to activate.
- To disable, confirm with a current code.

## Android app (WebView wrapper)
- Code lives in `android/` (Kotlin, SDK 34, minSdk 24).
- Open the `android` folder in Android Studio or run `./gradlew :app:assembleRelease` to produce an APK that opens https://schautrack.schauer.to/.
- If the site domain changes, update `START_URL` in `android/app/src/main/java/to/schauer/schautrack/MainActivity.kt` and the domain in `android/app/src/main/res/xml/network_security_config.xml`.

## Project layout
- `src/server.js` – Express server, routes, auth + 2FA, dashboard logic
- `views/` – EJS templates for auth, dashboard, 2FA
- `public/` – Stylesheet
- `db/init.sql` – Database schema (users, entries, session store)
- `docker-compose.yml` – App + Postgres stack
