# Full i18n + language selector — design spec

**Date:** 2026-07-19
**Branch:** `worktree-add-language-i18n` (off `staging`)
**Status:** approved design, ready for implementation plan
**Supersedes/implements:** `docs/i18n.md` (the prior proposal) — phases 0–4, 6, 7 of that doc, minus the backend API-error catalog (phase 5, explicitly deferred here).

---

## 1. Goal

Give Schautrack users real, working localization:

1. A **language selector in Settings** whose default option is **"Automatic (browser language)"**, overridable to a fixed language.
2. **Eight supported languages** with full UI translations: English (source/fallback), German, French, Spanish, Italian, Portuguese, Dutch, Polish.
3. **Localized transactional emails** in those eight languages, selected by the recipient's stored preference.

A language dropdown alone is cosmetic — the app is 100% hardcoded English today — so this work includes the full i18n machinery and the actual translated catalogs, not just the control.

## 2. Supported languages

| Code | Endonym (shown in the dropdown) |
|------|--------------------------------|
| `en` | English  *(source of truth, `fallbackLng`)* |
| `de` | Deutsch |
| `es` | Español |
| `fr` | Français |
| `it` | Italiano |
| `nl` | Nederlands |
| `pl` | Polski |
| `pt` | Português |

The dropdown's first option is **"Automatic (browser language)"** (value = empty). Language names are shown as **endonyms**, alphabetized by endonym after the Automatic entry.

`en` is always the source-of-truth locale and the i18next `fallbackLng`, so any missing key renders English rather than a raw key string.

## 3. Architecture

### 3.1 Client (React SPA — the bulk of the work)

- **Libraries:** `i18next`, `react-i18next`, `i18next-browser-languagedetector` (all React 19 + Vite compatible). Dev dependency `i18next-parser` for extraction/CI.
- **Init:** `client/src/i18n/index.ts` — configures resources, `fallbackLng: 'en'`, the detector, and namespaces. Imported once in `client/src/main.tsx` before `<App>` renders.
- **Every hardcoded English string** in `client/src` is replaced with a `t('key')` call (or `<Trans>` where interpolation/markup requires it), and its English text moves into a JSON catalog. This includes JSX text, toast/alert messages, `title`/`aria-label`/`placeholder` attributes, and the existing `lib/oidcMessages.ts` map (migrated into the `auth` catalog verbatim by key).

**Namespaces** (one JSON file per namespace per locale, so catalogs review independently and lazy-load):

| Namespace | Covers |
|-----------|--------|
| `common`    | Layout, `Footer`, nav, shared buttons, generic/shared toasts & errors, `App` loading screen |
| `auth`      | login / register / password reset / email verification / 2FA / OIDC (migrated `oidcMessages.ts`) / passkeys |
| `dashboard` | entries, weight, todos, notes, the plan/`PlanChart` feature |
| `settings`  | all Settings cards + Admin |
| `landing`   | Landing page + Legal (imprint / privacy / terms) |

**File layout:**

```
client/src/i18n/
  index.ts
  locales/
    en/{common,auth,dashboard,settings,landing}.json   # source of truth
    de/{...}.json
    es/{...}.json
    fr/{...}.json
    it/{...}.json
    nl/{...}.json
    pl/{...}.json
    pt/{...}.json
```

**Keys** are semantic and dotted, scoped by namespace, e.g. `footer.tagline`, `settings.i18n.language`, `auth.oidc.errors.invalid_state`. The OIDC map's existing string keys carry over verbatim.

### 3.2 Locale-aware formatting

- New `client/src/lib/format.ts` with `formatDate`, `formatTime`, `formatNumber` helpers driven by the **active i18next language** (via `Intl`), replacing the ad-hoc `new Date(...).toLocaleDateString()` calls that pass no locale.
- **Critical exclusion — do NOT localize data-key formatting.** The existing `toLocaleDateString('en-CA')` calls in `stores/dashboardStore.ts`, `pages/Dashboard/TodoList.tsx`, and `pages/Plan/PlanChart.tsx` produce `YYYY-MM-DD` strings used as **grouping/lookup keys**, not display. These MUST stay exactly as they are. Only genuine *display* dates/times/numbers route through `format.ts`.
- **Untouched (per project CLAUDE.md):** the calorie amount input keeps `inputmode="tel"`; `lib/mathParser.ts` and the numeric *input* path are not localized. We localize display only.

### 3.3 Persistence (`User.language`)

Mirror the existing **timezone** preference end-to-end (its wiring is the exact template):

1. **Migration** — add `language TEXT` (nullable) to the `users` table in `internal/database/migrations.go` (`ensureUserPrefsSchema` or a new sequential migration; runs under the startup advisory lock).
2. **Model** — add `Language *string` (or `string`) to the `User` struct in `internal/model/models.go`.
3. **Read path** — add the column to the `SELECT` list **and** the `Scan(...)` args in `internal/middleware/auth.go` `GetUserByID`.
4. **Serialize** — add `"language"` to the `userResp` map in `internal/handler/api.go` for both `Settings` and `Me`.
5. **Write path** — add `Language` to the `Preferences` request body struct in `internal/handler/settings.go`, **validate against the 8-code allow-list** (empty/absent = "Automatic" → store `NULL`), and add `language = $N` to the `UPDATE`.
6. **Client type** — add `language` to the `User` interface in `client/src/types/index.ts`.
7. **Client API** — extend `savePreferences` in `client/src/api/settings.ts`.

Semantics: `NULL`/empty stored value = **Automatic**; a non-null value = an explicit locale code.

### 3.4 Selector + autodetect behavior

- Control lives in `client/src/pages/Settings/PreferencesSettings.tsx` as a native `<select className={selectClass}>` matching the existing Weight Unit / Timezone controls, wired into the same `useAutosave` `data` memo and `savePreferences` call. No new UI component library — native `<select>`.
- **Resolution order on load:**
  1. Logged-in user with an explicit `user.language` → `i18n.changeLanguage(user.language)`.
  2. Otherwise (Automatic, or anonymous) → `i18next-browser-languagedetector` (`navigator.language`), `fallbackLng: en`.
- Selecting **"Automatic"** clears any `localStorage` language override so the browser language wins again; selecting a specific language sets it (and, when logged in, persists to `User.language`).
- `<html lang>` is updated live on every `languageChanged` event (replacing the static `lang="en"` in `client/index.html`), for screen readers and SEO.

### 3.5 Localized emails (Go backend)

- Externalize the four templates in `internal/service/email.go` — `SendVerificationEmail`, `SendEmailChangeVerification`, `SendPasswordResetEmail`, `Send2FAResetEmail` — into **per-locale template sets** (subject + text + HTML) using Go `text/template` + `html/template`, selected by the recipient user's `language` (fallback `en` when `NULL`/unknown).
- Layout suggestion: `internal/service/emailtemplates/<locale>/<name>.{subject,txt,html}.tmpl` embedded via `//go:embed`, with `en` as the fallback set. Exact structure finalized in the implementation plan.

## 4. Scope boundaries

**In scope:**
- All client UI strings across the five namespaces, 8 locales.
- `User.language` persistence + Automatic-with-override selector + `<html lang>` sync.
- Locale-aware **display** formatting via `format.ts`.
- Localized transactional emails (8 locales).
- CI guardrail (`i18next-parser` key-parity check) + an e2e language-switch test.

**Deferred (follow-up, NOT this work):**
- **Backend API error message catalog** + `Accept-Language` negotiation middleware. Raw backend error strings stay English for now; most user-facing errors are already mapped client-side via catalogs/`oidcMessages`.

**Out of scope (unchanged from `docs/i18n.md`):**
- RTL layout (no RTL target locale).
- Localizing user-generated content (entry names, notes, saved foods).
- Touching the calorie input mode / `mathParser` numeric input path.

## 5. Execution model — subagent fan-out

Four waves. Foundation is sequential; the two heavy waves fan out across parallel subagents (disjoint files, no shared-state collisions), then a verification wave.

- **Wave 0 — foundation (sequential, small).** Install libraries; create `i18n/index.ts` + empty-ish `en` catalogs; wrap the app with the provider; `format.ts`; the full `User.language` end-to-end wiring (migration → model → scan → serialize → save → client type/api); the selector wired against English. Build + typecheck green, English output unchanged.
- **Wave 1 — string extraction (5 parallel agents, one per namespace).** Each agent owns a disjoint set of components (`common`, `auth`, `dashboard`, `settings`, `landing`), converts hardcoded strings to `t()` keys, and writes that namespace's complete `en/<ns>.json`. Assigned by directory so file edits never overlap; each writes only its own catalog file.
- **Wave 2 — translation (7 parallel agents, one per target locale).** Runs only after the `en` catalogs are complete. Each agent reads the finished `en/*` catalogs and produces one locale's `de|es|fr|it|nl|pl|pt/*.json`, preserving keys, interpolation placeholders (`{{...}}`), and plural forms. Emails translated in the same wave (or a parallel per-locale email agent).
- **Wave 3 — verification.** `tsc` typecheck + `vite build` + `go build`/`go test`; `i18next-parser` run asserting no un-keyed literals and no missing keys per locale; a Playwright e2e test that switches language in Settings and asserts translated text appears + that Automatic follows the browser; spot-review of ≥2 non-English catalogs for placeholder/plural integrity.

## 6. Extraction & CI guardrail

- Add `i18next-parser` (client dev dependency) + config scanning `client/src`, plus an `i18n:extract` script.
- CI step fails the build if (a) extraction produces a diff (a literal was added without a key) or (b) a non-`en` locale is missing keys present in `en`. Slots into the existing `.github/workflows/build.yml`.
- Catalogs are committed JSON — no external TMS.

## 7. Safety property

English rendered output is **byte-for-byte identical** after the migration until a real translation is added — only the *source* of each string changes (literal → catalog lookup). Every wave leaves the app fully working; no screen is half-converted within a shippable step.

## 8. Verification / definition of done

- `tsc -b` typecheck clean; `vitest` unit suite green; `vite build` succeeds.
- `go build ./...` and `go test ./...` green.
- Settings shows the language dropdown; **Automatic** follows `navigator.language`; picking a language switches the UI live, persists for logged-in users, and updates `<html lang>`.
- All five namespaces fully keyed; all 7 non-`en` locales have full key parity with `en` (enforced by the CI guardrail).
- A verification email sent to a user whose `language=de` arrives in German; a user with `NULL` language gets English.
- Playwright e2e language-switch test passes.
