# Schautrack
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
git clone https://gitlab.com/schauer.to/schautrack.git
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
[`registry.gitlab.com/schauer.to/schautrack`](https://gitlab.com/schauer.to/schautrack/container_registry)

- **Production:** `registry.gitlab.com/schauer.to/schautrack:v1.2.3`
- **Staging:** `registry.gitlab.com/schauer.to/schautrack:staging-123`

## Android App

<a href="https://play.google.com/apps/testing/to.schauer.schautrack">
  <img src="https://play.google.com/intl/en_us/badges/static/images/badges/en_badge_web_generic.png" alt="Get it on Google Play" height="80">
</a>

Source code available at [schautrack-android](https://gitlab.com/schauer.to/schautrack-android).

## Environment Variables

Settings can be configured via environment variables (in .env or passed to the container). Some settings can also be changed by an admin in /admin. Environment variables always take precedence.

### Required

| Variable | Description |
|----------|-------------|
| `SESSION_SECRET` | Session encryption key (change in production!) |
| `SUPPORT_EMAIL` | Contact email shown on support/error pages |

### Database

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (e.g. `postgresql://user:pass@host:5432/db`) |

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

Photo-based calorie estimation with support for OpenAI, Claude, and Ollama.

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_KEY_ENCRYPTION_SECRET` | *(empty)* | AES-256-GCM key for encrypting user API keys (generate with: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`) |
| `AI_PROVIDER` | *(required)* | AI provider to use: `openai`, `claude`, or `ollama` |
| `AI_KEY` | *(empty)* | Global API key (fallback when users don't have their own) |
| `AI_ENDPOINT` | *(empty)* | Custom endpoint override (e.g., `http://your-ollama-host:11434/v1`). Leave blank to use provider defaults. |
| `AI_MODEL` | *(empty)* | Specify AI model to use (e.g., `gpt-4o-mini`, `claude-sonnet-4-20250514`, `gemma3:12b`). Required for OpenAI and Claude. |
| `AI_DAILY_LIMIT` | *(empty)* | Daily limit for AI requests per user when using global key (0 or empty = unlimited) |

**Note:** Ollama models must be downloaded before use. The docker-compose setup automatically pulls the model specified in `AI_MODEL`. Models specified only in API requests will fail if not pre-downloaded.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).
