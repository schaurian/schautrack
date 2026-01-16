# Schautrack

[![Build Status](https://github.com/schaurian/schautrack/actions/workflows/build.yml/badge.svg)](https://github.com/schaurian/schautrack/actions)
[![GitHub Release](https://img.shields.io/github/v/release/schaurian/schautrack)](https://github.com/schaurian/schautrack/releases)
[![License](https://img.shields.io/github/license/schaurian/schautrack)](LICENSE)
[![Docker Pulls](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/schaurian/schautrack/pkgs/container/schautrack)

Schautrack is a self-hostable, open-source, AI-powered calorie tracker for you and your friends.

**Try it:** [schautrack.schauer.to](https://schautrack.schauer.to)

![Dashboard](docs/screenshots/dashboard.png)

## Goals

Counting calories is painful. But it helps you reach your weight goals.

Schautrack is built to stay out of your way. Just enter your calories and stay under your daily goal. Or snap a photo and let AI estimate it for you.

## Features
- Log calories consumed or burned
- Daily calorie goals with progress tracking
- AI-powered calorie estimation from food photos (OpenAI, Claude, or Ollama)
- Weight tracking
- Account linking to share data with friends
- Real-time updates via SSE
- Docker and Kubernetes ready
- Android app on Google Play

## Quickstart (Docker)
1) Clone the repository:
```
git clone https://github.com/schaurian/schautrack.git
cd schautrack
```
2) Copy env template and adjust secrets as needed:
```
cp .env.example .env
```
3) Build and run:
```
docker compose up --build
```
4) App is available at http://localhost:3000

### Pre-built Images
Pre-built Docker images are available in the registry:
[`ghcr.io/schaurian/schautrack`](https://github.com/schaurian/schautrack/pkgs/container/schautrack)

- **Production:** `ghcr.io/schaurian/schautrack:latest` or `ghcr.io/schaurian/schautrack:v0.1.2`
- **Staging:** `ghcr.io/schaurian/schautrack:staging-4`

## Android App

<a href="https://play.google.com/apps/testing/to.schauer.schautrack">
  <img src="https://play.google.com/intl/en_us/badges/static/images/badges/en_badge_web_generic.png" alt="Get it on Google Play" height="80">
</a>

Source code available at [schautrack-android](https://github.com/schaurian/schautrack-android).

## Environment Variables

Settings can be configured via environment variables (in .env or passed to the container). Some settings can also be changed by an admin in /admin. Environment variables always take precedence.

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

### AI Features

Photo-based calorie estimation with support for OpenAI, Claude, and Ollama.

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_KEY_ENCRYPTION_SECRET` | *(empty)* | Random 32-byte hex string |
| `AI_PROVIDER` | *(empty)* | AI provider to use: `openai`, `claude`, or `ollama`. Required to enable AI features. |
| `AI_KEY` | *(empty)* | Global API key (fallback when users don't have their own) |
| `AI_ENDPOINT` | *(empty)* | Custom endpoint override (e.g., `http://your-ollama-host:11434/v1`). Leave blank to use provider defaults. |
| `AI_MODEL` | *(empty)* | Specify AI model to use (e.g., `gpt-4o-mini`, `claude-sonnet-4-20250514`, `gemma3:12b`). Required for OpenAI and Claude. |
| `AI_DAILY_LIMIT` | *(empty)* | Daily limit for AI requests per user when using global key (0 or empty = unlimited) |

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

### Legal Pages

| Variable | Default | Description |
|----------|---------|-------------|
| `ENABLE_LEGAL` | `false` | Set to `true` to enable `/imprint`, `/privacy`, `/terms` |
| `IMPRINT_URL` | `/imprint` | URL for imprint link |
| `IMPRINT_ADDRESS` | *(empty)* | Full name and address (use `\n` for line breaks) |
| `IMPRINT_EMAIL` | *(empty)* | Contact email (rendered as SVG for spam protection) |

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).
