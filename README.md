# Schautrack

[![Build Status](https://github.com/schaurian/schautrack/actions/workflows/build.yml/badge.svg)](https://github.com/schaurian/schautrack/actions)
[![GitHub Release](https://img.shields.io/github/v/release/schaurian/schautrack)](https://github.com/schaurian/schautrack/releases)
[![License](https://img.shields.io/github/license/schaurian/schautrack)](LICENSE)
[![Docker Pulls](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/schaurian/schautrack/pkgs/container/schautrack)

Schautrack is a self-hostable, open-source nutrition tracker — log calories, macros, and weight, set goals, and share progress with friends.

**Try it:** [schautrack.com](https://schautrack.com)

![Dashboard](docs/screenshots/dashboard.png)

## Goals

Tracking nutrition is tedious. But it helps you reach your goals.

Schautrack is built to stay out of your way. Log calories and macros, set goals, and let AI estimate from photos. Simple as that.

## Features

- Log calories and macros (protein, carbs, fat, fiber, sugar)
- Daily goals with color-coded progress tracking
- AI-powered nutrition estimation from food photos (OpenAI, Claude, or Ollama)
- Barcode scanning via OpenFoodFacts
- Weight tracking with unit preference (kg/lbs)
- Daily notes and recurring todos with streak tracking
- Account linking to share data with friends
- Two-factor authentication (TOTP) with backup codes
- Invite-only registration mode
- Real-time updates via Server-Sent Events (SSE)
- Docker and Kubernetes ready (~21MB image)
- Android app on Google Play

## Android App

<img src="https://play.google.com/intl/en_us/badges/static/images/badges/en_badge_web_generic.png" alt="Coming soon to Google Play" height="80" style="opacity: 0.5; filter: grayscale(100%);">

> **Want to test?** The app is currently in closed testing. Write "hi" with your Google Play email to [getschautrackapp@schauer.to](mailto:getschautrackapp@schauer.to) and I'll add you and send you the link. I really appreciate early testers - this will change to open access once we have enough users!

Source code available at [schautrack-android](https://github.com/schaurian/schautrack-android).

## Quickstart (Docker)

```bash
mkdir schautrack && cd schautrack
curl -O https://raw.githubusercontent.com/schaurian/schautrack/main/compose.yml
curl -O https://raw.githubusercontent.com/schaurian/schautrack/main/.env.example
mv .env.example .env
sed -i "s/please-change-me/$(openssl rand -hex 32)/" .env
docker compose up -d
```

App is available at http://localhost:8080.

## Kubernetes (Helm)

A Helm chart is available for Kubernetes deployments with bundled PostgreSQL.

```bash
helm repo add schautrack https://helm.schautrack.com
helm repo update
helm install schautrack schautrack/schautrack \
  --set config.sessionSecret="$(openssl rand -base64 32)" \
  --set postgresql.auth.password="$(openssl rand -base64 16)"
```

See [Helm Chart Documentation](helm/schautrack/README.md) for Ingress, TLS, external databases, AI configuration, and all parameters.

### Development Setup

To build from source instead of using pre-built images:

```bash
git clone https://github.com/schaurian/schautrack.git
cd schautrack
cp .env.example .env
docker compose -f compose.dev.yml up --build
```

## Environment Variables

Settings follow a strict priority hierarchy: **environment variables** > **admin panel** (`/admin`) > **user preferences**. When a higher-priority source sets a value, lower-priority sources are ignored and their UI controls are disabled.

### Required

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | *(empty)* | PostgreSQL connection string (e.g. `postgresql://user:pass@host:5432/db`) |
| `SESSION_SECRET` | *(empty)* | Random secret for session encryption |

### General

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Port to listen on |
| `ADMIN_EMAIL` | *(empty)* | Email that gets access to `/admin` page |
| `SUPPORT_EMAIL` | *(empty)* | Contact email shown on support/error pages |
| `BASE_URL` | *(auto-detect)* | Base URL for SEO meta tags (e.g., `https://schautrack.com`). Auto-detects from request if not set. |

### AI Features

Photo-based nutrition estimation with support for OpenAI, Claude, and Ollama.

> **Configuration priority:** Environment variables > admin panel settings > user settings. When any global AI config is set (provider or key), user personal AI settings are ignored. Users can only bring their own API key when no global config exists.

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_PROVIDER` | *(empty)* | AI provider to use: `openai`, `claude`, or `ollama`. Required to enable AI features. |
| `AI_KEY` | *(empty)* | Global API key (used by all users; overrides personal keys) |
| `AI_KEY_ENCRYPTION_SECRET` | *(empty)* | Random 32-byte hex string for encrypting user API keys |
| `AI_ENDPOINT` | *(empty)* | Custom endpoint override (e.g., `http://your-ollama-host:11434/v1`). Leave blank to use provider defaults. |
| `AI_MODEL` | *(empty)* | Specify AI model to use (e.g., `gpt-4o`, `claude-sonnet-4-5-20250929`, `gemma3:12b`). Required for OpenAI and Claude. |
| `AI_DAILY_LIMIT` | `10` | Daily limit for AI requests per user when using global key (0 = unlimited) |

**Note:** Ollama models must be downloaded before use. The docker-compose setup automatically pulls the model specified in `AI_MODEL`. Models specified only in API requests will fail if not pre-downloaded.

### SMTP (Password Reset)

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | *(empty)* | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | *(empty)* | SMTP username |
| `SMTP_PASS` | *(empty)* | SMTP password |
| `SMTP_FROM` | `SUPPORT_EMAIL` | From address for emails |
| `SMTP_SECURE` | `false` | Set to `true` for SSL/TLS |

### Features

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_BARCODE` | `true` | Enable barcode scanning via OpenFoodFacts. Set `false` to disable. |
| `ENABLE_REGISTRATION` | `open` | `open` (anyone can register) or `false` / `invite` (requires invite code). Also configurable via `/admin`. |

### OIDC (Single Sign-On)

Generic OpenID Connect — works with Google, Microsoft, GitHub, GitLab, Apple, Keycloak, Authentik, Authelia, Zitadel, or any OIDC-compliant provider. Users are auto-created on first login and auto-linked by email to existing accounts.

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_ISSUER` | *(empty)* | OIDC issuer URL (e.g., `https://accounts.google.com`). **Enables OIDC when set.** |
| `OIDC_CLIENT_ID` | *(empty)* | OAuth2 client ID |
| `OIDC_CLIENT_SECRET` | *(empty)* | OAuth2 client secret |
| `OIDC_LABEL` | *(derived)* | Button label. Defaults to a capitalized brand name inferred from the issuer host. |
| `OIDC_REQUIRE_INVITE` | `false` | Require invite code for OIDC registration (default: OIDC bypasses invite-only) |
| `OIDC_REDIRECT_URL` | *(auto)* | Callback URL. Auto-built as `<BASE_URL>/auth/oidc/callback` when unset. |

A logo is auto-selected from a small bundled set (Google, Microsoft, GitHub, GitLab, Apple, Keycloak, Authentik, Authelia, Zitadel) when the issuer URL contains the brand name. Otherwise the button shows text only.

**Example (Google):**
```env
OIDC_ISSUER=https://accounts.google.com
OIDC_CLIENT_ID=123456.apps.googleusercontent.com
OIDC_CLIENT_SECRET=GOCSPX-...
```

Add `https://<your-domain>/auth/oidc/callback` as an authorized redirect URI in your provider's OAuth client.

### Passkeys

WebAuthn-based passwordless login with biometric verification. Users can register up to 10 passkeys and use them as their primary login method. Passkeys skip 2FA since they are inherently multi-factor.

| Variable | Default | Description |
|----------|---------|-------------|
| `PASSKEYS_RP_ID` | *(empty)* | Relying Party ID — your domain (e.g., `schautrack.com`). **Enables passkeys when set.** |
| `PASSKEYS_RP_NAME` | `Schautrack` | Display name shown in passkey dialogs |
| `PASSKEYS_RP_ORIGINS` | `https://<RP_ID>` | Allowed origins (comma-separated, for multi-domain setups) |

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `TRUST_PROXY` | `true` | Trust `X-Forwarded-For` / `X-Real-Ip` headers for rate limiting. Set `false` for direct-access deployments without a reverse proxy. |
| `RATE_LIMIT_AUTH` | `10` | Max authentication attempts per minute per IP |

### Legal Pages

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_LEGAL` | `false` | Set to `true` to enable `/imprint`, `/privacy`, `/terms` |
| `IMPRINT_URL` | `/imprint` | URL for imprint link |
| `IMPRINT_ADDRESS` | *(empty)* | Full name and address (use `\n` for line breaks) |
| `IMPRINT_EMAIL` | *(empty)* | Contact email (rendered as SVG for spam protection) |

### SEO / Deployment

| Variable | Default | Description |
|----------|---------|-------------|
| `ROBOTS_INDEX` | `false` | Set to `true` to allow search engine indexing (default: noindex for self-hosters) |

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).
