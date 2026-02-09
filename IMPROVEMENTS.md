# Schautrack — Improvement Recommendations

*Generated 2026-02-09 by Clampy 🦞*

## Architecture 🏗️

### 1. Split server.js (3900 lines)
The monolith needs to go. Suggested structure:
- `routes/auth.js` — login, register, 2FA, password reset, email verification
- `routes/entries.js` — calorie CRUD
- `routes/weight.js` — weight CRUD  
- `routes/links.js` — account linking
- `routes/admin.js` — admin panel
- `routes/ai.js` — AI estimation
- `db/queries.js` — all SQL helper functions
- `lib/auth.js` — middleware, session helpers
- `lib/ai.js` — provider configs, estimation logic
- `lib/utils.js` — date formatting, parsing, etc.

**Priority: HIGH** — becoming unmaintainable

### 2. No tests
Zero test coverage. Critical paths that need tests:
- Registration + email verification flow
- Login + 2FA flow
- Calorie entry CRUD
- Account linking (request/accept/decline/remove)
- AI estimation (mock providers)
- Import/export
- Weight tracking
- Rate limiting / CAPTCHA logic

Consider: Jest + Supertest for integration tests.

**Priority: HIGH**

### 3. Schema migrations
The `ensureXxxSchema()` pattern works but doesn't scale. Issues:
- No rollback capability
- No migration history tracking
- Parallel migrations could race
- Hard to reason about state

Consider: `node-pg-migrate` or `knex` migrations.

**Priority: MEDIUM**

---

## Security 🔒

### 4. Function() eval in parseAmount()
```javascript
const value = Function('"use strict"; return (' + expr + ')')();
```
Despite the regex filter (`/^[0-9+\-*/().]+$/`), this is a code execution vector. Edge cases in JS parsing could bypass the filter.

**Fix:** Use `mathjs` library or write a simple recursive descent parser.

**Priority: HIGH** — security risk

### 5. Password minimum too low
6 characters is too weak for 2026. 

**Fix:** Minimum 10 characters. Consider checking against HaveIBeenPwned API or at least a common password list.

**Priority: MEDIUM**

### 6. No rate limiting
CAPTCHA after 3 failed logins is session-based — trivially bypassed with new sessions. No rate limiting on:
- `/login`
- `/register`
- `/forgot-password`
- `/api/ai/estimate`
- `/settings/email/request`

**Fix:** Add `express-rate-limit` with IP-based limiting. Example:
```javascript
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
app.post('/login', loginLimiter, async (req, res) => { ... });
```

**Priority: HIGH** — essential for public-facing app

### 7. bcrypt → argon2
bcrypt at 12 rounds is fine but argon2id is the modern standard. Not urgent but worth considering for new projects or a major version bump.

**Priority: LOW**

### 8. Reset token is 6-digit numeric
`generateResetCode()` produces a 6-digit number (100000-999999). That's only ~900K possibilities — brutable if rate limiting is missing (see #6).

**Fix:** Use longer tokens (UUID or 32-char hex) OR ensure strict rate limiting.

**Priority: MEDIUM** (mitigated if #6 is fixed)

---

## Performance ⚡

### 9. Admin settings queried every request
The middleware runs on every request:
```javascript
const effectiveSupportEmail = await getEffectiveSetting('support_email', supportEmail);
const effectiveEnableLegal = await getEffectiveSetting('enable_legal', process.env.ENABLE_LEGAL);
// ... 3 more queries
```
That's 5 DB queries per request just for settings.

**Fix:** In-memory cache with TTL:
```javascript
let settingsCache = null;
let settingsCacheTime = 0;
const CACHE_TTL = 60000; // 1 minute

async function getCachedSettings() {
  if (settingsCache && Date.now() - settingsCacheTime < CACHE_TTL) return settingsCache;
  // ... load from DB
  settingsCache = result;
  settingsCacheTime = Date.now();
  return result;
}
```

**Priority: MEDIUM**

### 10. No explicit connection pool limits
```javascript
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
```
Defaults to 10 connections. Should be explicit and documented.

**Priority: LOW**

### 11. SSE memory leak potential
`userEventClients` Map could accumulate stale connections if `close` event doesn't fire properly (network issues, etc.).

**Fix:** Add periodic cleanup (every 5 minutes, remove connections that haven't sent a ping response).

**Priority: LOW**

---

## Code Quality 📝

### 12. Inconsistent error handling
Some routes: `return res.redirect('/settings')`
Some routes: `return res.status(500).json({ ok: false })`
Some routes: silently swallow errors

**Fix:** Centralized error handling middleware:
```javascript
app.use((err, req, res, next) => {
  console.error(err);
  const wantsJson = (req.headers.accept || '').includes('application/json');
  if (wantsJson) return res.status(500).json({ ok: false, error: 'Internal error' });
  res.redirect('/dashboard');
});
```

**Priority: MEDIUM**

### 13. Manual type coercion everywhere
`toInt()` is called dozens of times. TypeScript would eliminate this entire class of bugs.

**Priority: LOW** (big migration, not worth it for this project size)

### 14. Duplicated link authorization checks
The "is user linked?" query is copy-pasted in:
- `/entries/day`
- `/overview`
- `/weight/day`
- Potentially more

**Fix:** Extract to middleware:
```javascript
const requireLinkAuth = async (req, res, next) => {
  const targetUserId = parseInt(req.query.user || req.params.user, 10);
  if (targetUserId === req.currentUser.id) return next();
  // ... check link exists
};
```

**Priority: MEDIUM**

### 15. AI timeout is 10 minutes
```javascript
const timeout = setTimeout(() => controller.abort(), 600000); // 10 minutes
```
Way too long for a food photo analysis. User will have left the page.

**Fix:** 30 seconds max. Maybe 15 for OpenAI/Claude, 60 for Ollama (local).

**Priority: LOW** (but easy fix)

---

## Features / UX 🎯

### 16. No API token auth for mobile
The Android app presumably needs auth. Sessions work for web but are awkward for mobile. 

**Fix:** Add JWT or API key auth as an alternative to session cookies.

**Priority: MEDIUM** (if Android app is active)

### 17. No pagination
`/entries/day` returns all entries. `/admin` loads all users. Will break at scale.

**Priority: LOW** (until you have heavy users)

### 18. Destructive import
Import deletes ALL existing entries before inserting new ones. No merge option.

**Fix:** Offer "Replace" vs "Merge" option. Or at minimum, create a backup export before importing.

**Priority: LOW**

### 19. No CSRF tokens
Using session validation for CSRF protection (per CLAUDE.md), but there's no actual CSRF token in forms. `sameSite: 'lax'` helps but doesn't fully prevent CSRF on same-site requests.

**Fix:** Add `csurf` middleware or manual CSRF tokens in forms.

**Priority: MEDIUM**

### 20. Account deletion doesn't clean everything
```javascript
await pool.query('DELETE FROM calorie_entries WHERE user_id = $1', [userId]);
await pool.query('DELETE FROM account_links WHERE requester_id = $1 OR target_id = $1', [userId]);
await pool.query('DELETE FROM users WHERE id = $1', [userId]);
```
Missing: `weight_entries`, `password_reset_tokens`, `email_verification_tokens`, `ai_usage`. The `ON DELETE CASCADE` on FK handles some, but `ai_usage` and tokens should be explicitly cleaned.

**Priority: MEDIUM**

---

## DevOps / Deployment 🚀

### 21. No health check for dependencies
`/api/health` checks DB but not SMTP or AI provider connectivity. Add optional deep health check.

**Priority: LOW**

### 22. Helm chart has no HPA
No horizontal pod autoscaler template. Fine for small deployments but worth adding.

**Priority: LOW**

### 23. No Prometheus metrics
No `/metrics` endpoint. Would be useful for monitoring request latency, error rates, AI usage.

**Priority: LOW**

---

## Summary — Priority Order

| # | Issue | Priority | Effort |
|---|-------|----------|--------|
| 4 | Function() eval in parseAmount | 🔴 HIGH | Small |
| 6 | No rate limiting | 🔴 HIGH | Small |
| 1 | Split server.js | 🔴 HIGH | Large |
| 2 | No tests | 🔴 HIGH | Large |
| 5 | Password minimum too low | 🟡 MEDIUM | Tiny |
| 8 | Weak reset tokens | 🟡 MEDIUM | Small |
| 9 | Settings queried every request | 🟡 MEDIUM | Small |
| 14 | Duplicated link auth | 🟡 MEDIUM | Small |
| 19 | No CSRF tokens | 🟡 MEDIUM | Small |
| 20 | Incomplete account deletion | 🟡 MEDIUM | Small |
| 12 | Inconsistent error handling | 🟡 MEDIUM | Medium |
| 3 | Schema migrations | 🟡 MEDIUM | Medium |
| 16 | No API token auth | 🟡 MEDIUM | Medium |
| 15 | AI timeout too long | 🟢 LOW | Tiny |
| 10 | Pool limits not explicit | 🟢 LOW | Tiny |
| 7 | bcrypt → argon2 | 🟢 LOW | Small |
| 11 | SSE memory leak | 🟢 LOW | Small |
| 17 | No pagination | 🟢 LOW | Small |
| 18 | Destructive import | 🟢 LOW | Small |
| 13 | Manual type coercion | 🟢 LOW | Large |
| 21 | Deep health check | 🟢 LOW | Small |
| 22 | Helm HPA | 🟢 LOW | Small |
| 23 | Prometheus metrics | 🟢 LOW | Medium |
| 24 | DB creds in compose default | 🟡 MEDIUM | Tiny |
| 25 | No network isolation in compose | 🟡 MEDIUM | Small |
| 26 | Helm secrets in plaintext | 🟡 MEDIUM | Small |
| 27 | No Content-Security-Policy | 🟡 MEDIUM | Small |
| 28 | Static assets no cache headers | 🟢 LOW | Tiny |
| 29 | No graceful shutdown | 🟡 MEDIUM | Small |
| 30 | CI: db/init.sql not in paths trigger | 🟢 LOW | Tiny |
| 31 | No input sanitization on EJS output | 🟡 MEDIUM | Medium |

---

## Additional Findings (Round 2)

### 24. Default DB credentials in compose
`compose.yml` uses `env_file: .env` and `.env.example` has `POSTGRES_PASSWORD=schautrack`. While the quickstart docs say to change it, many won't. The password is also the same as the username and DB name.

**Fix:** Generate random password in quickstart script (already done in README but not enforced).

**Priority: MEDIUM**

### 25. No network isolation in Docker Compose
The `db` service has no network restrictions — it's accessible from the host if Docker publishes ports. Should use internal networks:
```yaml
networks:
  internal:
    internal: true
  external:
```

**Priority: MEDIUM**

### 26. Helm chart stores secrets in ConfigMap
Looking at `templates/configmap.yaml` + `templates/secret.yaml` — good that secrets are in a Secret resource. But `values.yaml` stores `sessionSecret`, `smtp.pass`, `ai.key`, `postgresql.auth.password` as plaintext values. Users who commit their values file will leak secrets.

**Fix:** Document that `existingSecret` should be used in production. Add a warning comment in values.yaml.

**Priority: MEDIUM**

### 27. No Content-Security-Policy header
The Express app doesn't set CSP headers. For a food tracking app with file uploads and AI image processing, CSP would prevent XSS escalation.

**Fix:** Use `helmet` middleware (also adds other security headers).

**Priority: MEDIUM**

### 28. Static assets served without cache headers
`express.static` with no `maxAge` or `Cache-Control` configuration. Every page load re-downloads CSS/images.

**Fix:** `app.use(express.static(path.join(__dirname, 'public'), { maxAge: '7d' }))` — or use hashed filenames.

**Priority: LOW**

### 29. No graceful shutdown handling
No `SIGTERM`/`SIGINT` handlers. When the container stops, in-flight requests are dropped and DB connections aren't cleaned up. `dumb-init` handles signal forwarding but Node still needs to handle shutdown.

**Fix:**
```javascript
const server = app.listen(PORT);
process.on('SIGTERM', () => {
  server.close(() => pool.end());
});
```

**Priority: MEDIUM**

### 30. CI paths trigger missing db/init.sql
The GitHub Actions workflow only triggers on changes to `src/**`, `Dockerfile`, `package*.json`, `helm/**`. Changes to `db/init.sql` won't trigger a build, but `init.sql` is used by the dev compose and is part of the schema documentation.

**Priority: LOW**

### 31. EJS templates — potential XSS
EJS uses `<%= %>` which auto-escapes. Good. But check for any `<%- %>` (unescaped) usage in templates that might take user input. The `header.ejs` partial uses `<%- include() %>` which is fine, but any `<%- userContent %>` would be a vulnerability.

**Priority: MEDIUM** (need to audit all .ejs files for `<%-` with user data)
