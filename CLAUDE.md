# Claude Code Context

This document contains important context and decisions for Claude Code when working on this project.

## Project Overview

**Schautrack** is a calorie tracking web application built with Node.js, Express, and PostgreSQL. It supports:
- User authentication with optional 2FA (TOTP)
- Calorie entry tracking with daily goals
- AI-powered calorie estimation from food photos (OpenAI, Claude, or Ollama)
- Weight tracking
- Account linking to share data with other users
- Timezone-aware entry timestamps
- Real-time updates via Server-Sent Events (SSE)

## Project Structure

```
schautrack/
├── src/
│   ├── server.js          # Main application server
│   ├── views/             # EJS templates
│   │   ├── dashboard.ejs
│   │   ├── settings.ejs
│   │   ├── partials/
│   │   └── ...
│   └── public/            # Static assets
│       ├── style.css
│       ├── logo.png
│       └── ...
├── db/
│   └── init.sql           # Database schema
├── scripts/               # Build and deployment scripts
├── Dockerfile             # Optimized multi-stage build
├── docker-compose.yml     # Local development setup
├── .gitlab-ci.yml         # CI/CD pipeline (Kaniko-based)
└── package.json
```

**Important:** All application code lives in `src/`. Views and public assets were moved here to simplify the Docker build.

## Technology Stack

- **Runtime:** Node.js 22 (Alpine Linux)
- **Framework:** Express.js
- **Database:** PostgreSQL 18
- **Template Engine:** EJS
- **Session Store:** PostgreSQL (connect-pg-simple)
- **Authentication:** bcrypt + optional TOTP (speakeasy)
- **Real-time:** Server-Sent Events (SSE)

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
- Entry timestamps always display in the VIEWER's timezone (like Unix timestamps converted to local time)
- Timezone is auto-detected from client and persisted to DB
- When viewing linked user's entries, timestamps are converted to YOUR timezone, not theirs

### Docker Optimization
- Multi-stage build with Alpine base (171MB final image)
- Uses `dumb-init` for proper signal handling
- Comprehensive `.dockerignore` to exclude unnecessary files
- All app code in `src/` for simpler COPY command
- Runs as non-root `node` user

## CI/CD Pipeline

### GitLab CI
- **Runner:** Kubernetes-based (not Docker-in-Docker)
- **Builder:** Kaniko (works without privileged containers)
- **Branches:**
  - `main`: Builds with semver tags (v1.2.3) + latest
  - `staging`: Builds with `staging-{PIPELINE_IID}` tags
  - Other branches: Builds with commit SHA only

### Jobs
1. `semver-tag`: Creates version tags (main branch only)
2. `container-build-default`: Builds and pushes to registry (main)
3. `container-build-branch`: Builds for staging/feature branches
4. `registry-expiration-policy`: Manages container cleanup

### Known Issues
- Registry cleanup policy script uses form-encoded data (not JSON)
- Token `REGISTRY_POLICY_TOKEN` must be set in GitLab CI/CD variables
- Runner must support non-privileged containers (no Docker-in-Docker)

## Database Schema Notes

**Schema migrations are handled in code** via `ensureXxxSchema()` functions in `server.js` - no separate migration scripts or Kubernetes Jobs needed.

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
- **Three-tier key hierarchy:**
  1. User personal API key (encrypted in database)
  2. Global admin API key (set in admin panel or environment variable)
  3. Environment variable fallback
- **Custom endpoints:** Users can override default API endpoints for proxies or self-hosted deployments
- **Rate limiting:** Global API key usage is limited per user per day (configurable via `AI_DAILY_LIMIT`)

## Environment Variables

Required:
- `DATABASE_URL`: PostgreSQL connection string
- `SESSION_SECRET`: Session encryption key

Optional:
- `SUPPORT_EMAIL`: Contact email for support pages
- `IMPRINT_URL`: Custom imprint page URL (default: '/imprint')
- `IMPRINT_ADDRESS`: Full name and address text (rendered as SVG, use \n for line breaks)
- `IMPRINT_EMAIL`: Email text (rendered as SVG)
- `BUILD_VERSION`: Injected during build, displayed in footer

AI Configuration (Global Fallbacks):
- `AI_PROVIDER`: Default AI provider (`openai`, `claude`, or `ollama`)
- `AI_KEY`: Global API key (fallback when users don't have their own)
- `AI_ENDPOINT`: Optional custom endpoint override (leave blank to use provider defaults)
- `AI_MODEL`: Optional model override (e.g., `gpt-4o`, `claude-opus-4-20250514`, `gemma3:12b`)
- `AI_DAILY_LIMIT`: Daily AI request limit per user when using global key (default: unlimited)

## Development Workflow

### Branch Strategy
**IMPORTANT:** Never commit directly to `main`. Always work in the `staging` branch:
1. Make all changes and commits on the `staging` branch
2. Push to `staging` for testing
3. Once verified, merge `staging` into `main` and push
4. **Always switch back to `staging` after pushing to main**: `git checkout staging`

### Local Development
```bash
docker compose up -d --build
```
- Web app: http://localhost:3000
- PostgreSQL: localhost:5432
- Database initializes from `db/init.sql`

### Deployment
1. Push to `staging` branch to test on staging environment
2. Once staging is verified, merge to `main`: `git checkout main && git merge staging --no-edit && git push origin main`
3. CI automatically creates semver tags and builds containers
4. Deploy using tagged container images

**IMPORTANT:** Never auto-push to staging or main. The user handles all deployments manually.

## Code Patterns

### Timezone Usage
```javascript
// Get viewer's timezone (always use the current user's timezone)
const tz = getClientTimezone(req) || req.currentUser?.timezone || 'UTC';

// Format timestamps in viewer's timezone
const time = formatTimeInTz(entry.created_at, tz);

// Even for linked users, timestamps are shown in VIEWER's timezone
// This is like Unix timestamps - stored in UTC, displayed in local time
```

### SSE for Real-time Updates
- Endpoint: `/api/entries/stream`
- Sends updates when entries are added/modified/deleted
- Client reconnects automatically on disconnect
- Used for keeping linked user views in sync

## Common Tasks

### Adding a New Feature
1. Update database schema in `db/init.sql` if needed
2. Add route handler in `src/server.js`
3. Create/update EJS view in `src/views/`
4. Add styles to `src/public/style.css`
5. Test locally with `docker compose up -d --build`
6. Push to staging for integration testing
7. Merge to main when ready

### Styling Guidelines
- Use existing CSS variables for colors
- Mobile-first responsive design with `@media (max-width: 768px)`
- Consistent spacing scale: `--space-xs` (4px), `--space-sm` (8px), `--space-md` (12px), `--space-lg` (16px), `--space-xl` (24px)
- Dark theme with subtle gradients and glows

## Performance Considerations

- Database queries use parameterized statements (SQL injection prevention)
- Session store in PostgreSQL (not in-memory)
- Static assets served with Express.static
- Efficient SQL indexes on foreign keys and lookup columns
- Multi-stage Docker build keeps image size down

## Security Notes

- TOTP 2FA implementation using `speakeasy`
- Passwords hashed with bcrypt (10 rounds)
- Session cookies: httpOnly, secure (in production), sameSite: 'lax'
- CSRF protection via session validation
- Input validation on all user-submitted data
- Runs as non-root user in container

## Things to Remember

1. **Always** use the viewer's timezone when displaying timestamps (not the creator's)
2. **Never** commit `.env` files or secrets
3. **Always** test Docker builds after structural changes
4. **Use** Kaniko for CI builds (not Docker-in-Docker)
5. **Keep** all app code in `src/` directory
6. **Maintain** the blue-purple color scheme
7. **Never** auto-push to staging or main - user handles deployments
8. **Never** commit directly to main - always commit to staging first, then merge to main
9. **Footer quote:** "You got this. Trust me."
