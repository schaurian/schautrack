# Schautrack — Improvement Recommendations

*Updated 2026-02-11 after modular refactor*

## Medium — Should Fix

### 1. Duplicate helper functions across 3 files
`countAcceptedLinks()` and `getLinkRequests()` are copy-pasted in:
- `middleware/links.js`
- `middleware/settings.js`
- `routes/links.js`

**Fix:** Extract to `src/lib/links.js` and import everywhere.

**Priority: MEDIUM** — defeats the purpose of the modular refactor

### 2. No expiry on pending session data
`pendingRegistration` and `pendingEmailChange` stored in sessions have no TTL. A half-finished registration persists until the session expires (could be days). For email changes, an attacker could request a change, wait indefinitely, then verify later.

**Fix:** Add a `createdAt` timestamp and reject anything older than 30 minutes.

**Priority: MEDIUM** — security concern

### 3. Admin user deletion doesn't clean sessions
`routes/admin.js` deletes user rows from all tables but leaves their entries in the `sessions` table. The deleted user stays logged in until their session naturally expires.

**Fix:** Add `DELETE FROM sessions WHERE sess::jsonb->'userId' = $1` to the admin delete flow.

**Priority: MEDIUM** — security gap

### 4. Base64 image size not validated in AI route
`routes/ai.js` checks `startsWith('data:image/')` but doesn't limit the decoded size. Since images arrive via JSON body (not multer), the multer file size limit doesn't apply. Someone could POST a 100MB base64 string.

**Fix:** Check decoded base64 length before forwarding to AI provider. Reject anything over ~10MB.

**Priority: MEDIUM** — DoS vector

### 5. Schema migrations have no transaction wrapping
`db/migrations.js` runs migrations with individual queries. If a migration fails partway through, the schema is left in an inconsistent state with no rollback.

**Fix:** Wrap each migration function in `BEGIN`/`COMMIT` with `ROLLBACK` on error.

**Priority: MEDIUM**

### 6. Inconsistent error handling in auth routes
`routes/auth.js` has multiple code paths with different error patterns:
- Some call `renderLogin()`, some `res.render()` directly
- Some return after error, some fall through
- Password reset and email verification have divergent flows

**Fix:** Audit all error paths for consistency. Ensure every error branch returns.

**Priority: MEDIUM**

---

## Low — Nice to Have

### 7. SVG text rendering bug in utils.js
`textToSvg()` splits on `/\\n|\n/` — the double-escaped `\\n` matches a literal backslash+n in code, but environment variable values contain literal `\n` strings (not actual newlines). The regex works for env var strings but fails for actual newline characters passed programmatically.

**Fix:** Use `/\\n|\n/` consistently and document the expected input format.

**Priority: LOW**

### 8. No API token auth for mobile
Only session-based auth exists. Mobile apps (Android) need to manage cookies awkwardly.

**Fix:** Add JWT or API key auth as an alternative.

**Priority: LOW** (unless Android app is actively developed)

### 9. No pagination in admin panel
`routes/admin.js` loads all users at once. Will degrade with many users.

**Priority: LOW** — not a problem at current scale

### 10. No Prometheus metrics
No `/metrics` endpoint for monitoring request latency, error rates, or AI usage.

**Priority: LOW**

### 11. No Helm HPA template
No HorizontalPodAutoscaler in the Helm chart.

**Priority: LOW**

### 12. Math parser edge case
`lib/math-parser.js` doesn't handle `parseFloat("1e999")` → `Infinity`. Should add `Number.isFinite()` check after parsing numbers.

**Priority: LOW** — unlikely in practice

---

## Summary — Priority Order

| # | Issue | Priority | Effort |
|---|-------|----------|--------|
| 1 | Duplicate helper functions (3 files) | MEDIUM | Small |
| 2 | No expiry on pending session data | MEDIUM | Small |
| 3 | Admin delete doesn't clean sessions | MEDIUM | Tiny |
| 4 | Base64 image size not validated | MEDIUM | Small |
| 5 | Migrations have no transaction wrapping | MEDIUM | Small |
| 6 | Inconsistent error handling in auth | MEDIUM | Medium |
| 7 | SVG text rendering bug | LOW | Tiny |
| 8 | No API token auth for mobile | LOW | Medium |
| 9 | No admin pagination | LOW | Small |
| 10 | No Prometheus metrics | LOW | Medium |
| 11 | No Helm HPA | LOW | Small |
| 12 | Math parser Infinity edge case | LOW | Tiny |
