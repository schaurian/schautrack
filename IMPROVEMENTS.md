# Schautrack — Improvement Recommendations

*Updated 2026-02-11 after modular refactor*

## Medium — Should Fix

### 1. Inconsistent error handling in auth routes
`routes/auth.js` has multiple code paths with different error patterns:
- Some call `renderLogin()`, some `res.render()` directly
- Some return after error, some fall through
- Password reset and email verification have divergent flows

**Fix:** Audit all error paths for consistency. Ensure every error branch returns.

**Priority: MEDIUM**

---

## Low — Nice to Have

### 2. SVG text rendering input format
`textToSvg()` splits on `/\\n|\n/` — handles both literal `\n` strings from environment variables and real newline characters. Works correctly but the expected input format is undocumented.

**Priority: LOW** — cosmetic, not a bug

### 3. No pagination in admin panel
`routes/admin.js` loads all users at once. Will degrade with many users.

**Priority: LOW** — not a problem at current scale

### 4. No Prometheus metrics
No `/metrics` endpoint for monitoring request latency, error rates, or AI usage.

**Priority: LOW**

### 5. No Helm HPA template
No HorizontalPodAutoscaler in the Helm chart.

**Priority: LOW**

---

## Summary — Priority Order

| # | Issue | Priority | Effort |
|---|-------|----------|--------|
| 1 | Inconsistent error handling in auth | MEDIUM | Medium |
| 2 | SVG text input format docs | LOW | Tiny |
| 3 | No admin pagination | LOW | Small |
| 4 | No Prometheus metrics | LOW | Medium |
| 5 | No Helm HPA | LOW | Small |
