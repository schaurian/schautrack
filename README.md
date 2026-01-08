# Schautrack
Schautrack is a self-hostable, open-source, AI-powered calorie tracker for you and your friends.

**Try it:** [schautrack.schauer.to](https://schautrack.schauer.to)

![Dashboard](docs/screenshots/dashboard.png)

## Features
- Log calories consumed or burned
- Daily calorie goals with progress tracking
- AI-powered calorie estimation from food photos (OpenAI or Claude)
- Weight tracking
- Account linking to share data with friends
- Email + password auth with optional TOTP 2FA
- Timezone-aware timestamps
- Real-time updates via SSE
- Docker and Kubernetes ready
- Android app on Google Play

## Quickstart (Docker)
1) Clone the repository:
```
git clone https://gitlab.com/florianschauer/schautrack.git
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

## Android App

<a href="https://play.google.com/apps/testing/to.schauer.schautrack">
  <img src="https://play.google.com/intl/en_us/badges/static/images/badges/en_badge_web_generic.png" alt="Get it on Google Play" height="80">
</a>

The app is open source - build it yourself from [schautrack-android](https://gitlab.com/florianschauer/schautrack-android).

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

### Postgres (Docker Compose)

These are used by the Postgres container in docker-compose.yml:

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_DB` | `schautrack` | Database name |
| `POSTGRES_USER` | `schautrack` | Database user |
| `POSTGRES_PASSWORD` | `schautrack` | Database password |

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
| `AI_DAILY_LIMIT` | `*(empty)*` | Daily limit for AI requests per user |

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).
