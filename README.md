# Schautrack
Schautrack is an open-source, AI-powered calorie tracker.

## Features
- Email + password auth with optional TOTP 2FA (QR setup + disable flow)
- Log calories as positive (consumed) or negative (burned), with custom dates
- Dashboard shows today's progress and a 14-day goal hit/miss overview
- AI-powered calorie estimation from food photos (OpenAI or Claude)
- Weight tracking with daily entries
- Account linking to share data with other users
- Timezone-aware entry timestamps
- Real-time updates via Server-Sent Events (SSE)
- Postgres-backed sessions and data
- Dockerized app + database

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
