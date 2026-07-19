# Legal Compliance Pass — Privacy, Terms, Imprint, Consent

**Date:** 2026-07-19
**Branch:** `worktree-legal-compliance` (off `staging` @ 3a4a141, includes the weight planner)
**Status:** Approved (user delegated decisions); this doc doubles as the implementation plan.

> **Not legal advice.** This brings the pages and flows in line with the standard
> GDPR + German-law checklist (Art. 9/13 GDPR, §§ 307 ff. BGB, § 36 VSBG,
> § 18 MStV). A lawyer should review the result for actual assurance.

## Why now

The weight planner (shipped today) stores **height, birth year, sex, activity
level, and weight goals** — together with weight/nutrition logs this is GDPR
**Art. 9 special-category (health) data**. The current privacy policy does not
mention it, states no legal bases (Art. 13(1)(c)), and registration collects **no
consent or terms acceptance at all** (Art. 7(1) requires demonstrable consent).
The Terms' blanket `"as is" without warranty` clause is unenforceable against
German consumers (§§ 307 ff. BGB).

## Verified facts the copy relies on

- CAPTCHA is self-generated SVG — **no third-party CAPTCHA** (`internal/service/captcha.go`).
- **No analytics/tracking** anywhere in the client. Claims in the policy hold.
- Data export exists (Settings → Export) → portability claim is real.
- Planner math (BMR/TDEE/budget) is computed **server-side in-process**; body
  metrics are never sent to any third party (AI photos are the only outbound
  personal data, already documented).
- Footer legal links are unconditional; `GET /api/registration-info` is the
  existing client hook for register-time flags.
- Registration is two-step (`credentials` → `captcha`), user INSERT at
  `internal/handler/auth.go:391`.

## Changes

### 1. `client/src/pages/Legal/Privacy.tsx`
- Data We Collect: add body metrics (height, birth year, sex, activity level)
  and weight goals; note they are optional and power the planner.
- New section **“Health Data”**: what qualifies (weight, body metrics, goals,
  nutrition intake), computed locally, shared with no one, explicit-consent
  basis (Art. 9(2)(a)), withdrawal = delete the data or the account (as easy as
  giving it, Art. 7(3)); consent is collected at registration.
- New section **“Legal Bases”** (Art. 13(1)(c)): Art. 6(1)(b) service data;
  Art. 6(1)(f) security logs + rate limiting; Art. 9(2)(a) health data.
- Controller line (operator per Imprint), export/portability mention in Rights,
  `Last updated: 2026-07-19`.

### 2. `client/src/pages/Legal/Terms.tsx`
- Replace the `"as is"` sentence with a German-consumer-valid **liability
  clause**: unlimited for intent, gross negligence, injury to life/body/health,
  Product Liability Act; slight negligence only for cardinal obligations capped
  at typical foreseeable damage; otherwise excluded.
- New sections: **Eligibility (16+)**; **Termination** (user: delete anytime;
  operator: suspend/terminate for abuse with notice where reasonable);
  **Availability** (free service, no SLA, may be discontinued with reasonable
  notice and time to export).
- Extend **Not Medical Advice** to name the weight planner: calorie budgets/
  ETAs are formula-based estimates, not medical guidance; not suitable for
  managing eating disorders or medical conditions; consult a professional
  before a weight-loss program.
- `Last updated: 2026-07-19`.

### 3. `client/src/pages/Legal/Imprint.tsx`
- Keep the SVG address/email (deliberate spam protection).
- Add “Responsible for content pursuant to § 18 (2) MStV” (reuses address SVG).
- Add § 36 VSBG statement: not willing/obliged to participate in dispute
  resolution before a consumer arbitration board.

### 4. Registration consent (makes the paper enforceable)
- **Server** `internal/handler/api.go` `RegistrationInfo`: add
  `legalEnabled` (true when `enable_legal` effective setting is `"true"`).
- **Server** `internal/handler/auth.go`: body gains
  `legal_accepted`/`health_consent` bools. In `registerCredentials`, when legal
  is enabled both must be true → else 400 (“You must accept the terms and
  consent to health-data processing to register.”). Stash in session; at the
  user INSERT set `legal_accepted_at = NOW(), health_consent_at = NOW()`.
- **Migration** `ensureConsentSchema` (in `migrationSteps()`, sequential):
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS legal_accepted_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS health_consent_at TIMESTAMPTZ`.
- **Client** `Register.tsx`: when `legalEnabled`, two required checkboxes
  (Art. 7(2) distinguishable): (a) accept Terms + Privacy (links), (b) explicit
  consent to health-data processing with withdrawal note. Submit blocked until
  both checked; flags sent with the credentials step.
- Self-hosters without `ENABLE_LEGAL`: no checkboxes, no enforcement — unchanged.

### 5. Planner metrics notice (existing users)
`client/src/pages/Plan/MetricsForm.tsx`: one muted line above Save Details:
“Optional health data, processed only to compute your plan (Art. 9(2)(a) GDPR
consent). Remove it anytime by clearing the fields or deleting your account.”

### Known limitation (documented, not in scope)
OIDC first-login account creation bypasses the consent checkboxes (needs a
consent interstitial). Tracked as follow-up; password registration is the only
open path on schautrack.com today (registration is invite-gated).

## Verification
- `go build/vet/test ./...`; client `npm run build`.
- Live stack (compose.test.yml): register with legal enabled → checkboxes
  required → timestamps set in DB; register with legal disabled → unchanged;
  legal pages render; `e2e/legal.spec.ts` + `e2e/register.spec.ts` +
  `e2e/plan.spec.ts` green. New e2e assertions for the consent flow.
