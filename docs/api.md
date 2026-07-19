# Schautrack HTTP API Reference

Schautrack's backend is a **JSON-only HTTP API** (no server-side rendering). It is
consumed by the bundled React SPA and by external clients such as
[schautrack-android](https://github.com/schaurian/schautrack-android).

This document is a reference for that API. It is derived directly from the route
registrations in [`cmd/server/main.go`](../cmd/server/main.go) — that file is the
single source of truth. When in doubt, read the route table there and the handler
in `internal/handler/`.

- **Base path:** all endpoints are served from the application root (default port
  `3000`, override with `PORT`). Behind the reverse proxy the app is reached over
  HTTPS at your `BASE_URL`.
- **Content type:** requests and responses are `application/json` (exceptions:
  `/imprint/*.svg` return SVG, `/robots.txt` and `/sitemap.xml` return text/XML,
  `/events/entries` is a `text/event-stream`).
- **Request body limit:** 15 MB globally (`MaxBodySize` middleware); JSON bodies are
  additionally capped at 10 MB by `ReadJSON`.

---

## Authentication & sessions

Authentication is **session-cookie based** (there are no bearer tokens or API keys
for the app's own API).

- **Cookie name:** `schautrack.sid`
- **Attributes:** `HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` (set automatically
  when the request arrives over HTTPS / `X-Forwarded-Proto: https`).
- **Lifetime:** an anonymous session cookie lives 15 minutes; after a successful
  login it is regenerated and lives 30 days.
- A client must persist and send this cookie on every subsequent request. On
  successful `POST /api/auth/login` (or a passwordless register) the server issues a
  new authenticated `Set-Cookie`.

### Login flow

1. `GET /api/csrf` to obtain a CSRF token (see below).
2. `POST /api/auth/login` with `{ "email", "password" }`.
   - **Success (no 2FA):** `200 { "ok": true }` and a new session cookie.
   - **2FA enabled:** `200 { "ok": true, "requireToken": true }` — call
     `POST /api/auth/login` again with `{ "token": "<TOTP or backup code>" }` on the
     same session.
   - **Email not verified:** `200 { "ok": true, "requireVerification": true }`.
   - **Captcha demanded** (after repeated failures): `{ "ok": false,
     "requireCaptcha": true, "captchaSvg": "<svg>" }` — resubmit with a `captcha`
     field.
   - **Bad credentials:** `401 { "ok": false, "error": "..." }`.

Endpoints protected by `RequireLogin` return `401 { "error": "Authentication
required" }` when no valid session is present.

### Federated (OIDC) and passkey sessions

- OIDC and passkey routes are **only registered when configured** (`OIDC_*` /
  `PASSKEYS_*` env vars). If the feature is disabled the routes return `404`.
- A session created via OIDC has `auth_method = "oidc"`. Routes guarded by
  `RequireLocalAuth` (password/2FA/passkey/email management) return
  `403 { "error": "Log in with a password to change authentication settings." }`
  for such sessions.

### Step-up (sudo) re-authentication

Sensitive actions (change password, enable/disable 2FA, regenerate backup codes,
export/import/delete account, register/delete a passkey, request an email change,
unlink OIDC) require **fresh** primary auth. If the session has not re-authenticated
recently, the guarded endpoint returns:

```json
HTTP/1.1 403 Forbidden
{
  "error": "step_up_required",
  "requireStepUp": true,
  "methods": ["password", "passkey", "oidc"],
  "totpRequired": true
}
```

`methods` lists the elevation methods available to the current user. The client then
completes one of them and retries the original request:

- **Password (+ TOTP):** `POST /api/auth/step-up`
- **Passkey:** `POST /api/auth/step-up/passkey/begin` then `.../finish`
- **OIDC:** `GET /auth/oidc/step-up`

---

## CSRF protection

All **state-changing** requests (`POST`) that pass through the `CsrfProtection`
middleware require a CSRF token. `GET`/`HEAD`/`OPTIONS` are exempt.

1. `GET /api/csrf` → `200 { "token": "<hex token>" }`. The token is stored in the
   session, so the request must carry the session cookie.
2. Send the token in the **`X-CSRF-Token`** request header on every protected `POST`.

A missing or mismatched token returns `403 { "error": "Invalid CSRF token" }`.

> Note: `POST /api/ai/estimate` is **not** behind `CsrfProtection` (it is protected
> by login + the strict rate limiter only), so it does not require the header. Every
> other `POST` in the endpoint tables below marked "CSRF" does.

---

## Rate limiting

Three limiters are applied per client IP (the client IP is taken from
`X-Forwarded-For`/`X-Real-Ip` when `TRUST_PROXY=true`, the default):

| Limiter  | Default limit | Window     | Applied to |
|----------|---------------|------------|------------|
| auth     | 10 (`RATE_LIMIT_AUTH`)   | 15 minutes | login, register, step-up |
| strict   | 5 (`RATE_LIMIT_STRICT`)  | 5 minutes  | forgot/reset password, reset-2fa, email-change request, AI estimate |
| barcode  | 30            | 1 minute   | barcode lookup |

Exceeding a limit returns `429 Too Many Requests`.

---

## Shared users (linked accounts)

Read endpoints marked **link-aware** accept an optional `?user=<id>` query parameter
to view a linked user's data. Access is allowed only if the two accounts have an
`accepted` link; otherwise the endpoint returns `403 { "ok": false, "error": "Not
authorized" }`. Without `?user=`, the endpoint returns the caller's own data.

---

## Response & error conventions

Most JSON handlers use a small envelope:

- **Success:** `{ "ok": true, ... }` (extra fields vary per endpoint), or a bare
  resource object for read endpoints.
- **Error:** `{ "ok": false, "error": "<human-readable message>" }`.

A few middleware-level errors use a bare `{ "error": "..." }` shape (CSRF, login
required, admin required, step-up).

Common status codes:

| Status | Meaning |
|--------|---------|
| 200 | Success |
| 400 | Invalid request / validation error |
| 401 | Not authenticated (`{ "error": "Authentication required" }`) |
| 403 | CSRF failure, not admin, local-auth required, or step-up required |
| 404 | Not found (unknown `/api/*` or `/events/*` path, or missing resource) |
| 409 | Conflict (e.g. account already exists) |
| 429 | Rate limited |
| 500 | Server error |
| 503 | Health check failing / shutting down |

Any non-`/api/`, non-`/events/` `GET` that does not match a route falls through to
the SPA and returns `index.html`. Unknown `/api/*` and `/events/*` paths return `404`.

---

## Endpoint reference

Legend for the **Auth** column:
`Public` = no auth · `Session` = valid login required · `Admin` = admin only ·
`+CSRF` = requires `X-CSRF-Token` · `+StepUp` = requires fresh step-up ·
`+Local` = local (non-OIDC) session required · `link-aware` = accepts `?user=` ·
`(auth)`/`(strict)`/`(barcode)` = rate limiter applied.

### Public / meta

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | Public | Liveness/readiness: pings the DB. `200` with `{app,status,version,pool}` or `503` on DB failure / shutdown. |
| GET | `/api/latest-version` | Public | Latest released version tag from GitHub, cached: `{ "latest": "x.y.z" \| null }`. |
| GET | `/api/csrf` | Public | Issue/return the session CSRF token: `{ "token": "..." }`. |
| GET | `/api/me` | Session¹ | Current user profile + flags; `401 { "ok": false, "error": "Not authenticated" }` if no session. |
| GET | `/api/auth/registration-info` | Public | `{ "registrationEnabled": bool, "inviteRequired": bool }`. |
| GET | `/api/auth/info` | Public | Available auth methods: `{ "passkeysEnabled": bool, "oidc": {label,slug,logo} \| null }`. |
| GET | `/api/auth/captcha` | Public | Returns a fresh captcha challenge for the current session. |
| GET | `/robots.txt` | Public | SEO robots file (indexing gated by `ROBOTS_INDEX`). |
| GET | `/sitemap.xml` | Public | SEO sitemap. |
| GET | `/imprint/address.svg` | Public | Imprint address rendered as SVG. |
| GET | `/imprint/email.svg` | Public | Imprint email rendered as SVG. |

¹ `/api/me` is registered without the `RequireLogin` middleware; the handler itself
returns `401` when unauthenticated.

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/login` | Public +CSRF (auth) | Log in; multi-step for 2FA / verification / captcha (see Login flow). |
| POST | `/api/auth/register` | Public +CSRF (auth) | Register; two steps (`step: "credentials"` then `step: "captcha"`). |
| POST | `/api/auth/logout` | Session +CSRF | Destroy the session. |
| POST | `/api/auth/forgot-password` | Public +CSRF (strict) | Send a password-reset email. |
| POST | `/api/auth/reset-password` | Public +CSRF (strict) | Complete a password reset with a code. |
| POST | `/api/auth/verify-email` | Public +CSRF | Verify email with a code. |
| POST | `/api/auth/verify-email/resend` | Public +CSRF | Resend the verification email. |
| POST | `/api/auth/reset-2fa` | Public +CSRF (strict) | Begin/complete 2FA reset by email. |
| POST | `/api/auth/step-up` | Session +CSRF (auth) | Step up with password (+ TOTP). |
| POST | `/api/auth/step-up/passkey/begin` | Session +CSRF (auth) | Begin passkey step-up (passkeys enabled only). |
| POST | `/api/auth/step-up/passkey/finish` | Session +CSRF (auth) | Finish passkey step-up (passkeys enabled only). |

### OIDC (only when `OIDC_*` configured)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/oidc/login` | Public | Start the OIDC login redirect. |
| GET | `/auth/oidc/callback` | Public | OIDC redirect callback. |
| GET | `/auth/oidc/step-up` | Session | Re-authenticate via the IdP for step-up. |
| POST | `/settings/oidc/unlink` | Session +Local +StepUp +CSRF | Unlink the OIDC identity. |

### Passkeys / WebAuthn (only when `PASSKEYS_*` configured)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/passkeys/login/begin` | Public | Begin a passwordless passkey login. |
| POST | `/passkeys/login/finish` | Public | Finish a passwordless passkey login. |
| POST | `/passkeys/register/begin` | Session +Local +StepUp +CSRF | Begin registering a new passkey. |
| POST | `/passkeys/register/finish` | Session +Local +CSRF | Finish registering a new passkey. |
| POST | `/passkeys/delete` | Session +Local +StepUp +CSRF | Delete a passkey. |
| POST | `/passkeys/rename` | Session +Local +CSRF | Rename a passkey. |
| GET | `/passkeys/list` | Session | List the user's passkeys. |

### Entries

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/dashboard` | Session | Dashboard data for the current user. |
| GET | `/overview` | Session, link-aware | Overview/aggregate view. |
| GET | `/entries/day` | Session, link-aware | Calorie entries for a given day. |
| POST | `/entries` | Session +CSRF | Create a calorie / macro / weight entry. |
| POST | `/entries/{id}/update` | Session +CSRF | Update an entry. |
| POST | `/entries/{id}/delete` | Session +CSRF | Delete an entry. |
| GET | `/events/entries` | Session | Server-Sent Events stream of entry changes for the user. |

### Weight

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/weight/day` | Session, link-aware | Weight entry for a given day. |
| POST | `/weight/upsert` | Session +CSRF | Create or update a weight entry for a date. |
| POST | `/weight/{id}/delete` | Session +CSRF | Delete a weight entry. |

### Todos

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/todos` | Session | List todos. |
| POST | `/api/todos` | Session +CSRF | Create a todo. |
| POST | `/api/todos/{id}/update` | Session +CSRF | Update a todo. |
| POST | `/api/todos/{id}/delete` | Session +CSRF | Delete a todo. |
| POST | `/api/todos/{id}/toggle` | Session +CSRF | Toggle a todo's completion for a day. |
| POST | `/api/todos/reorder` | Session +CSRF | Reorder todos. |
| POST | `/api/todos/toggle-enabled` | Session +CSRF | Enable/disable the todos feature for the user. |
| GET | `/api/todos/day` | Session, link-aware | Todos for a given day. |

### Saved foods

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/saved-foods` | Session | List saved foods. |
| POST | `/api/saved-foods` | Session +CSRF | Create a saved food. |
| POST | `/api/saved-foods/{id}/update` | Session +CSRF | Update a saved food. |
| POST | `/api/saved-foods/{id}/delete` | Session +CSRF | Delete a saved food. |
| POST | `/api/saved-foods/{id}/track` | Session +CSRF | Log an entry from a saved food. |
| POST | `/api/entries/{id}/save-as-food` | Session +CSRF | Save an existing entry as a reusable food. |

### Notes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/notes/day` | Session, link-aware | Note for a given day. |
| POST | `/api/notes` | Session +CSRF | Create/update the note for a day. |
| POST | `/api/notes/toggle-enabled` | Session +CSRF | Enable/disable the notes feature for the user. |

### AI & barcode

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/ai/estimate` | Session (strict) | Estimate calories/macros from a food photo/description. **No CSRF header.** |
| GET | `/api/barcode/{code}` | Session (barcode) | Look up a product by barcode (only when `ENABLE_BARCODE != false`). |

### Settings & account

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/settings` | Session | Full settings payload for the user. |
| POST | `/settings/preferences` | Session +CSRF | Update preferences (timezone, goal, units, …). |
| POST | `/settings/macros` | Session +CSRF | Update macro tracking settings. |
| POST | `/settings/ai` | Session +CSRF | Update the user's AI provider/key/model. |
| POST | `/settings/password` | Session +Local +StepUp +CSRF | Change password. |
| POST | `/2fa/setup` | Session +Local +CSRF | Begin TOTP 2FA setup. |
| POST | `/2fa/cancel` | Session +Local +CSRF | Cancel an in-progress 2FA setup. |
| POST | `/2fa/enable` | Session +Local +StepUp +CSRF | Enable 2FA. |
| POST | `/2fa/disable` | Session +Local +StepUp +CSRF | Disable 2FA. |
| POST | `/2fa/backup-codes` | Session +Local +StepUp +CSRF | Regenerate backup codes. |
| POST | `/settings/email/request` | Session +Local +StepUp +CSRF (strict) | Request an email-address change. |
| POST | `/settings/email/verify` | Session +Local +CSRF | Verify the new email with a code. |
| POST | `/settings/email/cancel` | Session +Local +CSRF | Cancel a pending email change. |
| POST | `/settings/export` | Session +StepUp +CSRF | Export all account data. |
| POST | `/settings/import` | Session +StepUp +CSRF | Import account data. |
| POST | `/delete` | Session +StepUp +CSRF | Delete the account. |

### Account links

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/settings/link/request` | Session +CSRF | Request a link to another account. |
| POST | `/settings/link/respond` | Session +CSRF | Accept/decline a link request. |
| POST | `/settings/link/remove` | Session +CSRF | Remove an existing link. |
| POST | `/links/{id}/label` | Session +CSRF | Set a custom label on a link. |

### Admin (admin user only)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/admin` | Admin | Admin dashboard data. |
| POST | `/admin/settings` | Admin +CSRF | Update global settings (registration mode, AI defaults, …). |
| GET | `/admin/invites` | Admin | List invite codes. |
| POST | `/admin/invites` | Admin +CSRF | Create an invite code. |
| POST | `/admin/invites/{id}/delete` | Admin +CSRF | Delete an invite code. |
| POST | `/admin/users/{id}/delete` | Admin +CSRF | Delete a user. |

---

## Selected request/response shapes

The examples below are verified against the current handlers. Fields not listed here
should be confirmed against the handler in `internal/handler/`.

### `GET /api/health`

```json
{
  "app": "schautrack",
  "status": "ok",
  "version": "1.2.3",
  "pool": { "totalCount": 4, "idleCount": 3, "waitingCount": 0 }
}
```

`status` is `"ok"` (200), `"error"` (503, DB unreachable) or `"shutting_down"`
(503, during graceful shutdown).

### `GET /api/csrf`

```json
{ "token": "3f2a…" }
```

Send the value back as the `X-CSRF-Token` header on protected `POST` requests.

### `GET /api/me`

```json
{
  "user": {
    "id": 1,
    "email": "user@example.com",
    "timezone": "Europe/Berlin",
    "weightUnit": "kg",
    "dailyGoal": 2000,
    "totpEnabled": false,
    "macrosEnabled": { "calories": true },
    "macroGoals": {},
    "goalThreshold": 0,
    "preferredAiProvider": null,
    "hasAiKey": false,
    "hasGlobalAiKey": false,
    "hasGlobalAiConfig": false,
    "aiModel": null,
    "aiDailyLimit": null,
    "todosEnabled": false,
    "notesEnabled": false,
    "passkeyCount": 0,
    "oidcLinked": false,
    "authMethod": "password"
  },
  "isAdmin": false,
  "pendingLinkRequests": 0
}
```

### `POST /api/auth/login`

Request:

```json
{ "email": "user@example.com", "password": "secret", "token": "", "captcha": "" }
```

- Provide `email` + `password` first.
- Provide `token` (TOTP or backup code) on the follow-up request when the first
  response returned `requireToken: true`.
- Provide `captcha` when a response returned `requireCaptcha: true`.

Responses: `200 { "ok": true }` on success (with a new session cookie); or one of
`{ "ok": true, "requireToken": true }`, `{ "ok": true, "requireVerification": true }`,
`{ "ok": false, "requireCaptcha": true, "captchaSvg": "…" }`; or
`401 { "ok": false, "error": "…" }`.

### `POST /api/auth/register`

Two-step. Step 1:

```json
{ "step": "credentials", "email": "u@example.com", "password": "≥10 chars",
  "timezone": "Europe/Berlin", "invite_code": "" }
```

→ `200 { "ok": true, "requireCaptcha": true, "captchaSvg": "…" }`.

Step 2:

```json
{ "step": "captcha", "captcha": "<answer>" }
```

→ `200 { "ok": true }` (logged in) or `{ "ok": true, "requireVerification": true }`
when SMTP is configured. `409` if the account already exists.

### `POST /api/auth/logout`

No body. Requires `X-CSRF-Token`. → `200 { "ok": true }` and clears the cookie.

### `POST /entries`

Request (all fields optional but at least one of calories/macros/weight required):

```json
{
  "amount": "500",
  "entry_name": "Lunch",
  "entry_date": "2026-07-12",
  "weight": "72.5",
  "protein_g": 30,
  "carbs_g": 40,
  "fat_g": 10
}
```

- `amount` (calories) accepts a number or arithmetic string; max magnitude 9999.
- Macro fields are `protein_g`, `carbs_g`, `fat_g`, `fiber_g`, `sugar_g`; each 0–999.
- `entry_date` is `YYYY-MM-DD`; defaults to today in the user's timezone.
- When macro auto-calc is enabled, calories are computed from macros.

→ `200 { "ok": true }`.

### `POST /entries/{id}/update`

Request contains any subset of `name`, `amount`, and the macro `*_g` fields.
→ `200 { "ok": true, "entry": { "id", "date", "amount", "time", "name", "macros" } }`;
`404 { "ok": false, "error": "Entry not found" }` if the entry is not owned by the caller.

### `POST /entries/{id}/delete`

No body. → `200 { "ok": true }` or `404` if not found.

---

## Server-Sent Events

`GET /events/entries` (requires login) opens a long-lived `text/event-stream`. The
server pushes events when the user's entries change (also used to keep linked-user
views in sync). Clients should reconnect automatically on disconnect.
</content>
</invoke>
