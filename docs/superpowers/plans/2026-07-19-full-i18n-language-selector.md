# Full i18n + Language Selector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship real, working localization for Schautrack — a Settings language selector defaulting to "Automatic (browser language)", full UI translations in 8 languages, and localized transactional emails.

**Architecture:** `i18next` + `react-i18next` + `i18next-browser-languagedetector` on the React SPA (strings live in per-namespace JSON catalogs, `en` is source & fallback); a nullable `users.language` column wired exactly like the existing timezone preference; locale-aware *display* formatting via a new `format.ts`; per-locale Go email templates. Work fans out: foundation first (sequential), then string extraction per namespace (parallel), then translation per locale (parallel), then verification.

**Tech Stack:** React 19 · Vite 8 · TypeScript · Tailwind v4 · react-router 8 · TanStack Query · zustand · Go 1.26 (chi, pgx/PostgreSQL) · vitest · Playwright.

## Global Constraints

- **Locales (8):** `en` (source-of-truth + `fallbackLng`), `de`, `es`, `fr`, `it`, `nl`, `pl`, `pt`. Dropdown shows endonyms: English, Deutsch, Español, Français, Italiano, Nederlands, Polski, Português.
- **English output must stay byte-for-byte identical** after each extraction step — only the *source* of a string changes (literal → `t()` lookup). No screen half-converted within a committed step.
- **Do NOT localize data-key date formatting.** The `toLocaleDateString('en-CA')` calls in `client/src/stores/dashboardStore.ts`, `client/src/pages/Dashboard/TodoList.tsx`, and the plan chart produce `YYYY-MM-DD` *lookup keys*, not display — leave them exactly as-is. Only genuine display dates/times/numbers route through `format.ts`.
- **Do NOT touch** the calorie amount input mode (`inputmode="tel"`) or `client/src/lib/mathParser.ts` numeric-input path. Localize display only.
- **UI dropdowns are native `<select>`** styled with the shared `selectClass`, never Radix Select.
- `Automatic` = empty string in the UI / `NULL` in the DB. A non-null value is an explicit locale code from the 8-code allow-list.
- Backend API-error message catalog is **out of scope** (deferred). Raw backend error strings stay English.
- All work on branch `worktree-add-language-i18n`. Commit after each task.

---

## File Structure

**Created:**
- `client/src/i18n/index.ts` — i18next init (glob-loaded resources, detector, `SUPPORTED_LANGUAGES`, `<html lang>` sync).
- `client/src/i18n/locales/{en,de,es,fr,it,nl,pl,pt}/{common,auth,dashboard,settings,landing}.json` — catalogs (40 files).
- `client/src/lib/format.ts` — locale-aware display formatting helpers.
- `client/src/lib/format.test.ts` — vitest unit tests for the helpers.
- `client/i18next-parser.config.js` — extraction config.
- `internal/handler/settings_language_test.go` — Go test for language validation.
- `internal/service/emailtemplates/{en,de,es,fr,it,nl,pl,pt}/*.tmpl` — per-locale email templates.
- `internal/service/email_i18n_test.go` — Go test for locale template selection.
- `e2e/language-switch.spec.ts` — Playwright test.

**Modified:**
- `client/src/main.tsx` — import `./i18n` before `<App>`.
- `client/index.html` — `<html lang="en">` stays as the SSR default (JS updates it at runtime).
- `client/src/App.tsx` — resolve active language once the user loads.
- `client/src/pages/Settings/PreferencesSettings.tsx` — add the language `<select>`.
- `client/src/api/settings.ts` — extend `savePreferences`.
- `client/src/types/index.ts` — add `language` to `User`.
- `internal/model/models.go` — add `Language *string`.
- `internal/database/migrations.go` — add `language` column.
- `internal/middleware/auth.go` — add `language` to SELECT + Scan.
- `internal/handler/api.go` — add `"language"` to both user maps.
- `internal/handler/settings.go` — add `Language` to `Preferences` body, validate, UPDATE.
- `internal/service/email.go` — take a `lang` arg, render per-locale templates.
- `.github/workflows/build.yml` — add the catalog key-parity CI check.
- `client/package.json` — add deps + `i18n:extract` script.

---

# WAVE 0 — Foundation (sequential)

### Task 1: i18next scaffold + provider + language detector + `<html lang>` sync

**Files:**
- Create: `client/src/i18n/index.ts`
- Create: `client/src/i18n/locales/en/common.json` (+ empty `{}` for the other 4 en namespaces: `auth.json`, `dashboard.json`, `settings.json`, `landing.json`)
- Modify: `client/src/main.tsx`
- Modify: `client/package.json` (deps)

**Interfaces:**
- Produces: `i18n` (default export, the configured instance); `SUPPORTED_LANGUAGES: { code: string; endonym: string }[]`; `isSupportedLanguage(code: string): boolean`. Later tasks import these from `@/i18n`.

- [ ] **Step 1: Install libraries**

Run in `client/`:
```bash
npm install i18next react-i18next i18next-browser-languagedetector
npm install -D i18next-parser
```
Expected: packages added, `npm run typecheck` still clean.

- [ ] **Step 2: Create the en catalog files**

Create `client/src/i18n/locales/en/common.json`:
```json
{
  "footer": { "tagline": "One day at a time" }
}
```
Create `client/src/i18n/locales/en/auth.json`, `dashboard.json`, `settings.json`, `landing.json` each containing exactly:
```json
{}
```

- [ ] **Step 3: Create `client/src/i18n/index.ts`**

```ts
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

// Endonyms shown in the language dropdown. `en` first, rest alphabetized by endonym.
export const SUPPORTED_LANGUAGES: { code: string; endonym: string }[] = [
  { code: 'en', endonym: 'English' },
  { code: 'de', endonym: 'Deutsch' },
  { code: 'es', endonym: 'Español' },
  { code: 'fr', endonym: 'Français' },
  { code: 'it', endonym: 'Italiano' },
  { code: 'nl', endonym: 'Nederlands' },
  { code: 'pl', endonym: 'Polski' },
  { code: 'pt', endonym: 'Português' },
];

const SUPPORTED_CODES = SUPPORTED_LANGUAGES.map((l) => l.code);
export function isSupportedLanguage(code: string): boolean {
  return SUPPORTED_CODES.includes(code);
}

// Eagerly load every locale/namespace JSON so adding a file needs no wiring here.
const modules = import.meta.glob('./locales/*/*.json', { eager: true }) as Record<
  string,
  { default: Record<string, unknown> }
>;
const resources: Record<string, Record<string, Record<string, unknown>>> = {};
for (const path in modules) {
  const match = path.match(/\.\/locales\/([^/]+)\/([^/]+)\.json$/);
  if (!match) continue;
  const [, lng, ns] = match;
  (resources[lng] ??= {})[ns] = modules[path].default;
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: 'en',
    supportedLngs: SUPPORTED_CODES,
    nonExplicitSupportedLngs: true, // 'de-DE' -> 'de'
    load: 'languageOnly',
    ns: ['common', 'auth', 'dashboard', 'settings', 'landing'],
    defaultNS: 'common',
    interpolation: { escapeValue: false }, // React already escapes
    detection: {
      order: ['localStorage', 'navigator'],
      caches: ['localStorage'],
      lookupLocalStorage: 'i18nextLng',
    },
    returnNull: false,
  });

// Keep <html lang> in sync for screen readers / SEO.
const applyHtmlLang = (lng: string) => {
  document.documentElement.lang = lng.split('-')[0];
};
applyHtmlLang(i18n.language || 'en');
i18n.on('languageChanged', applyHtmlLang);

export default i18n;
```

- [ ] **Step 4: Import i18n in `main.tsx`**

Add this import to `client/src/main.tsx` (with the other `@/` imports, before `App` is used):
```ts
import '@/i18n';
```

- [ ] **Step 5: Verify build + typecheck**

Run in `client/`: `npm run typecheck && npm run build`
Expected: both succeed. App renders identically (no visible change yet).

- [ ] **Step 6: Commit**
```bash
git add client/src/i18n client/src/main.tsx client/package.json client/package-lock.json
git commit -m "feat(i18n): scaffold i18next + react-i18next + browser detector"
```

---

### Task 2: Locale-aware display formatting helpers

**Files:**
- Create: `client/src/lib/format.ts`
- Create: `client/src/lib/format.test.ts`

**Interfaces:**
- Produces: `activeLocale(): string`; `formatDate(value, locale?, opts?): string`; `formatTime(value, locale?, opts?): string`; `formatNumber(value, locale?, opts?): string`. Extraction-wave tasks route *display* date/number formatting through these.

- [ ] **Step 1: Write the failing test — `client/src/lib/format.test.ts`**
```ts
import { describe, it, expect } from 'vitest';
import { formatNumber, formatDate } from './format';

describe('formatNumber', () => {
  it('groups by locale', () => {
    expect(formatNumber(1234.5, 'en-US')).toBe('1,234.5');
    expect(formatNumber(1234.5, 'de')).toBe('1.234,5');
  });
});

describe('formatDate', () => {
  it('formats a fixed date per locale', () => {
    const iso = '2026-07-19T00:00:00Z';
    const opts: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' };
    expect(formatDate(iso, 'en-US', opts)).toBe('July 19, 2026');
    expect(formatDate(iso, 'de', opts)).toBe('19. Juli 2026');
  });
});
```

- [ ] **Step 2: Run it — expect FAIL** (`cannot find module './format'`)

Run in `client/`: `npx vitest run src/lib/format.test.ts`

- [ ] **Step 3: Implement `client/src/lib/format.ts`**
```ts
import i18n from '@/i18n';

/** The active UI locale (falls back to 'en'). */
export function activeLocale(): string {
  return i18n.language || 'en';
}

export function formatDate(
  value: string | number | Date,
  locale: string = activeLocale(),
  opts: Intl.DateTimeFormatOptions = { year: 'numeric', month: 'short', day: 'numeric' },
): string {
  const d = value instanceof Date ? value : new Date(value);
  return new Intl.DateTimeFormat(locale, opts).format(d);
}

export function formatTime(
  value: string | number | Date,
  locale: string = activeLocale(),
  opts: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit' },
): string {
  const d = value instanceof Date ? value : new Date(value);
  return new Intl.DateTimeFormat(locale, opts).format(d);
}

export function formatNumber(
  value: number,
  locale: string = activeLocale(),
  opts?: Intl.NumberFormatOptions,
): string {
  return new Intl.NumberFormat(locale, opts).format(value);
}
```

- [ ] **Step 4: Run tests — expect PASS**

Run in `client/`: `npx vitest run src/lib/format.test.ts`
Expected: 2 tests pass.

- [ ] **Step 5: Commit**
```bash
git add client/src/lib/format.ts client/src/lib/format.test.ts
git commit -m "feat(i18n): locale-aware display formatting helpers"
```

---

### Task 3: Backend `User.language` — column, model, read & write paths

**Files:**
- Modify: `internal/database/migrations.go` (`ensureUserPrefsSchema`)
- Modify: `internal/model/models.go` (`User` struct)
- Modify: `internal/middleware/auth.go` (`GetUserByID`)
- Modify: `internal/handler/api.go` (both user maps: `Me` ~line 88, `Settings` ~line 158)
- Modify: `internal/handler/settings.go` (`Preferences`)
- Create: `internal/handler/settings_language_test.go`

**Interfaces:**
- Produces: `User.Language *string` (JSON `language`); `POST /settings/preferences` now accepts `language` and validates it against the 8-code allow-list (empty ⇒ stored `NULL`); `/api/me` and `/api/settings` return `language` (string or `null`).

- [ ] **Step 1: Add the column** — in `internal/database/migrations.go`, extend the `ALTER TABLE users ADD COLUMN IF NOT EXISTS ...` list in `ensureUserPrefsSchema`:
```go
		ALTER TABLE users
			ADD COLUMN IF NOT EXISTS timezone TEXT,
			ADD COLUMN IF NOT EXISTS weight_unit TEXT,
			ADD COLUMN IF NOT EXISTS timezone_manual BOOLEAN DEFAULT FALSE,
			ADD COLUMN IF NOT EXISTS language TEXT;
```

- [ ] **Step 2: Add the model field** — in `internal/model/models.go`, in the `User` struct after `TimezoneManual`:
```go
	Language            *string         `json:"language"`
```

- [ ] **Step 3: Add to the read path** — in `internal/middleware/auth.go` `GetUserByID`, add `language` to the SELECT list (after `timezone_manual`) and `&u.Language` to the `Scan(...)` args in the matching position:
```go
	// SELECT ... timezone, weight_unit, timezone_manual, language,
	// Scan(... &u.Timezone, &u.WeightUnit, &u.TimezoneManual, &u.Language,
```
(Keep column order and scan order aligned — insert `language` immediately after `timezone_manual` in both.)

- [ ] **Step 4: Serialize in both user maps** — in `internal/handler/api.go`, add to BOTH the `Me` map (~line 92, after `"weightUnit"`) and the `Settings` `userResp` map (~line 162, after `"weightUnit"`):
```go
			"language":            user.Language,
```

- [ ] **Step 5: Write the failing Go test — `internal/handler/settings_language_test.go`**

Test the pure validation helper (added in Step 6). Write:
```go
package handler

import "testing"

func TestNormalizeLanguage(t *testing.T) {
	cases := map[string]string{
		"de":  "de",
		"EN":  "en",
		" fr ": "fr",
		"":    "",     // Automatic
		"xx":  "",     // unsupported -> Automatic
		"de-DE": "de", // region stripped
	}
	for in, want := range cases {
		if got := normalizeLanguage(in); got != want {
			t.Errorf("normalizeLanguage(%q) = %q, want %q", in, got, want)
		}
	}
}
```

- [ ] **Step 6: Run it — expect FAIL** (`undefined: normalizeLanguage`)

Run: `go test ./internal/handler/ -run TestNormalizeLanguage`

- [ ] **Step 7: Implement validation + wire into `Preferences`** — in `internal/handler/settings.go`:

Add the helper (package-level):
```go
var supportedLanguages = map[string]bool{
	"en": true, "de": true, "es": true, "fr": true,
	"it": true, "nl": true, "pl": true, "pt": true,
}

// normalizeLanguage returns a supported locale code, or "" for Automatic.
func normalizeLanguage(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.IndexAny(s, "-_"); i >= 0 {
		s = s[:i]
	}
	if s == "" || !supportedLanguages[s] {
		return ""
	}
	return s
}
```
Add `Language string \`json:"language"\`` to the `Preferences` body struct. Compute `lang := normalizeLanguage(body.Language)`. Change the UPDATE statements to also set `language`, storing `NULL` when `lang == ""`:
```go
	var langArg any
	if lang != "" {
		langArg = lang
	} // else langArg stays nil -> NULL

	if tz != "" {
		_, err := h.Pool.Exec(r.Context(),
			"UPDATE users SET weight_unit = $1, timezone = $2, timezone_manual = TRUE, language = $3 WHERE id = $4",
			unit, tz, langArg, user.ID)
		// ... existing error handling
	} else {
		_, err := h.Pool.Exec(r.Context(),
			"UPDATE users SET weight_unit = $1, language = $2 WHERE id = $3",
			unit, langArg, user.ID)
		// ... existing error handling
	}
```

- [ ] **Step 8: Run tests — expect PASS**

Run: `go test ./internal/handler/ -run TestNormalizeLanguage && go build ./...`
Expected: test passes, build clean.

- [ ] **Step 9: Commit**
```bash
git add internal/
git commit -m "feat(i18n): persist User.language end-to-end (column, model, read/write)"
```

---

### Task 4: Language selector UI + active-language resolution

**Files:**
- Modify: `client/src/types/index.ts` (`User`)
- Modify: `client/src/api/settings.ts` (`savePreferences`)
- Modify: `client/src/pages/Settings/PreferencesSettings.tsx`
- Modify: `client/src/App.tsx`

**Interfaces:**
- Consumes: `SUPPORTED_LANGUAGES`, `isSupportedLanguage` from `@/i18n` (Task 1); `User.language` from the API (Task 3).
- Produces: a working Settings language control; app-wide active language driven by `user.language` (explicit) or the browser (Automatic).

- [ ] **Step 1: Add `language` to the `User` type** — in `client/src/types/index.ts`, inside `interface User` after `weightUnit`:
```ts
  language: string | null;
```

- [ ] **Step 2: Extend `savePreferences`** — in `client/src/api/settings.ts`:
```ts
export function savePreferences(data: { weight_unit: string; timezone: string; language: string }) {
  return api<{ ok: boolean }>('/settings/preferences', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}
```

- [ ] **Step 3: Resolve active language on user load** — in `client/src/App.tsx`, add an effect (after the `fetchUser` effect). Import `i18n` and `isSupportedLanguage` at top: `import i18n, { isSupportedLanguage } from '@/i18n';`
```tsx
  // Apply the logged-in user's explicit language preference. When it's null
  // ("Automatic"), leave i18next's browser detection in charge.
  useEffect(() => {
    const pref = user?.language;
    if (pref && isSupportedLanguage(pref) && i18n.language !== pref) {
      i18n.changeLanguage(pref);
    }
  }, [user?.language]);
```

- [ ] **Step 4: Add the selector to `PreferencesSettings.tsx`**

Add imports:
```tsx
import { useTranslation } from 'react-i18next';
import i18n, { SUPPORTED_LANGUAGES } from '@/i18n';
```
Add state (next to the others) — dropdown value is `''` for Automatic:
```tsx
  const [language, setLanguage] = useState<string>(user.language ?? '');
```
Include it in the `data` memo and the save call:
```tsx
  const data = useMemo(() => ({ timezone, weightUnit, language }), [timezone, weightUnit, language]);
  const saveFn = useCallback(async (d: typeof data) => {
    await savePreferences({ weight_unit: d.weightUnit, timezone: d.timezone, language: d.language });
    onSave();
  }, [onSave]);
```
Add an `onChange` that switches the live UI language immediately:
```tsx
  const onLanguageChange = (code: string) => {
    setLanguage(code);
    if (code === '') {
      localStorage.removeItem('i18nextLng'); // let the browser decide again
      const detected = (navigator.language || 'en').split('-')[0];
      i18n.changeLanguage(detected);
    } else {
      i18n.changeLanguage(code);
    }
  };
```
Render the control as the first field inside the card's `<div className="flex flex-col gap-3">`:
```tsx
        <div className="flex flex-col gap-1.5">
          <label htmlFor="pref-language" className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{t('settings.i18n.language')}</label>
          <select id="pref-language" value={language} onChange={(e) => onLanguageChange(e.target.value)} className={selectClass}>
            <option value="">{t('settings.i18n.automatic')}</option>
            {SUPPORTED_LANGUAGES.map((l) => <option key={l.code} value={l.code}>{l.endonym}</option>)}
          </select>
        </div>
```
Add `const { t } = useTranslation('settings');` at the top of the component. Seed the two keys now in `client/src/i18n/locales/en/settings.json`:
```json
{
  "i18n": { "language": "Language", "automatic": "Automatic (browser language)" }
}
```
(The card heading `Internationalization` and the Weight Unit / Timezone labels get their keys in the Task 8 `settings` sweep.)

- [ ] **Step 5: Verify typecheck + build**

Run in `client/`: `npm run typecheck && npm run build`
Expected: both clean.

- [ ] **Step 6: Manual smoke (documented)** — Run the app (`docker compose -f compose.dev.yml up` or the project's dev flow). In Settings, confirm: the Language dropdown shows Automatic + 8 endonyms; selecting one flips the two seeded labels; reload keeps the choice; selecting Automatic reverts to the browser language. (Full e2e added in Task 19.)

- [ ] **Step 7: Commit**
```bash
git add client/src/types/index.ts client/src/api/settings.ts client/src/pages/Settings/PreferencesSettings.tsx client/src/App.tsx client/src/i18n/locales/en/settings.json
git commit -m "feat(i18n): Settings language selector with Automatic + live switch"
```

---

# WAVE 1 — String extraction (parallel: one agent per namespace)

**Shared procedure for every Wave-1 task.** Each task owns a disjoint set of components and one catalog file, so they never edit the same file.

For each user-facing English string in the assigned components:
1. Replace the literal with a `t('<key>')` call. Add `const { t } = useTranslation('<ns>');` to components that don't have it. For strings with markup or interpolation, use `<Trans>` or `t('key', { var })` with `{{var}}` placeholders.
2. Add the key + English value to `client/src/i18n/locales/en/<ns>.json`, using semantic dotted keys grouped by component/area.
3. Cover: JSX text, toast/alert messages, `title` / `aria-label` / `placeholder` / `alt` attributes, button labels, validation copy, empty-states.
4. **Leave data-key `toLocaleDateString('en-CA')` calls untouched.** Route genuine *display* dates/numbers through `@/lib/format`.
5. Do **not** touch the calorie input mode or `mathParser`.

**Definition of done per task:** `npm run typecheck && npm run build` clean; no user-facing English literal remains in the assigned files (spot-grep); rendered English is unchanged; the `en/<ns>.json` file is complete and valid JSON.

**Representative before/after** (applies to all Wave-1 tasks):
```tsx
// before — components/Layout/Footer.tsx
<div className="text-sm font-semibold text-foreground">One day at a time</div>
<a href="/imprint">Imprint</a>
// after
const { t } = useTranslation('common');
<div className="text-sm font-semibold text-foreground">{t('footer.tagline')}</div>
<a href="/imprint">{t('footer.imprint')}</a>
// common.json += { "footer": { "tagline": "One day at a time", "imprint": "Imprint" } }
```

Each task ends with:
```bash
git add client/src/i18n/locales/en/<ns>.json client/src/<assigned-paths>
git commit -m "feat(i18n): extract <ns> strings to en catalog"
```

### Task 5: Extract `common` namespace
**Scope:** `client/src/App.tsx` (LoadingScreen), `client/src/components/Layout/**` (Footer, nav/header), `client/src/components/ui/**` shared button/label text, `client/src/stores/toastStore.ts` shared toast text, and any generic error/empty-state strings shared across pages. Catalog: `client/src/i18n/locales/en/common.json`.

### Task 6: Extract `auth` namespace
**Scope:** login / register / password-reset / email-verification / 2FA / passkey / OIDC pages and components, **and migrate `client/src/lib/oidcMessages.ts` into `auth.json`** under `oidc.errors.*` / `oidc.settings.*` (keys carry over verbatim; replace the `Record` lookups with `t('oidc.errors.'+code, { ns: 'auth' })`). Catalog: `client/src/i18n/locales/en/auth.json`.

### Task 7: Extract `dashboard` namespace
**Scope:** `client/src/pages/Dashboard/**`, `client/src/pages/Plan/**`, weight/entries/todos/notes components and their stores' user-facing strings. Route display dates/numbers through `@/lib/format`; leave `en-CA` data keys. Catalog: `client/src/i18n/locales/en/dashboard.json`.

### Task 8: Extract `settings` namespace
**Scope:** all `client/src/pages/Settings/**` cards (Macro, Preferences card heading + Weight-Unit/Timezone labels, AI, Email, Password, 2FA, Passkeys, Todos, Notes, SavedFoods, OIDC, Links, Data, Danger) **and** `client/src/pages/Admin*`. Merge into the existing `settings.json` (which already has the `i18n.*` keys from Task 4 — do not clobber them). Catalog: `client/src/i18n/locales/en/settings.json`.

### Task 9: Extract `landing` namespace
**Scope:** `client/src/pages/Landing*`, `client/src/pages/Legal*` (imprint / privacy / terms), and any marketing/footer-adjacent copy not already in `common`. Catalog: `client/src/i18n/locales/en/landing.json`.

---

# WAVE 2 — Translation (parallel: one agent per locale) + emails

### Tasks 10–16: Translate `en` catalogs → each target locale

**Precondition:** Wave 1 complete — all five `en/*.json` are final.

**Procedure (identical per locale, disjoint output files):** For locale `<L>` in {`de`, `es`, `fr`, `it`, `nl`, `pl`, `pt`}, read all five `client/src/i18n/locales/en/*.json` and write `client/src/i18n/locales/<L>/{common,auth,dashboard,settings,landing}.json` with:
- **Every key from `en` present** (full parity — no missing keys).
- Natural, product-appropriate translation of each value. Keep the app's tone (concise, friendly).
- **Interpolation placeholders `{{var}}` preserved verbatim**, and i18next plural suffixes (`_one`/`_other`) kept where `en` uses them, translated per the locale's plural rules.
- **Do not translate:** brand name "Schautrack", proper nouns, URLs, code/keys, or units symbols (`kg`, `lb`) that are values not prose.
- Endonyms in `SUPPORTED_LANGUAGES` are already correct — do not touch `i18n/index.ts`.

**Verify per task:** `npm run typecheck && npm run build` clean, and the parity check (Task 18's script, run standalone) shows zero missing keys for `<L>`.

**Concrete example (de):**
```json
// en/common.json -> de/common.json
{ "footer": { "tagline": "One day at a time", "imprint": "Imprint" } }
// becomes
{ "footer": { "tagline": "Ein Tag nach dem anderen", "imprint": "Impressum" } }
```

Each task commits: `git commit -m "feat(i18n): add <L> translations"` (files `client/src/i18n/locales/<L>/`).

- [ ] Task 10: `de` · [ ] Task 11: `es` · [ ] Task 12: `fr` · [ ] Task 13: `it` · [ ] Task 14: `nl` · [ ] Task 15: `pl` · [ ] Task 16: `pt`

---

### Task 17: Localized transactional emails (Go)

**Files:**
- Create: `internal/service/emailtemplates/{en,de,es,fr,it,nl,pl,pt}/{verification,email_change,password_reset,twofa_reset}.{subject,txt,html}.tmpl`
- Modify: `internal/service/email.go`
- Create: `internal/service/email_i18n_test.go`
- Modify: callers of the four `Send*Email` functions (grep for call sites).

**Interfaces:**
- Produces: `Send*Email(email, code, lang string)` — each selects the locale template set (`normalizeEmailLang(lang)` → supported code or `en`) and renders subject/text/html. Fallback `en` when `lang` is `""`/unknown.

- [ ] **Step 1: Extract the current English templates** into `emailtemplates/en/*.tmpl`, embed with `//go:embed emailtemplates`. `verification.txt.tmpl` example (`{{.Code}}` replaces `%s`):
```
Your verification code is: {{.Code}}

This code expires in 30 minutes.

If you did not create this account, you can ignore this email.
```
Create matching `.subject.tmpl` (`Verify Your Email - Schautrack`) and `.html.tmpl` (the existing HTML with `{{.Code}}`), for all four templates.

- [ ] **Step 2: Write the failing test — `internal/service/email_i18n_test.go`**
```go
package service

import "testing"

func TestRenderEmailLocale(t *testing.T) {
	de, err := renderEmail("verification", "de", map[string]any{"Code": "123456"})
	if err != nil { t.Fatal(err) }
	if de.Subject == "" || !containsCode(de.Text, "123456") {
		t.Errorf("de verification render bad: %+v", de)
	}
	// unknown locale falls back to en
	fb, _ := renderEmail("verification", "xx", map[string]any{"Code": "1"})
	en, _ := renderEmail("verification", "en", map[string]any{"Code": "1"})
	if fb.Subject != en.Subject { t.Errorf("fallback != en: %q vs %q", fb.Subject, en.Subject) }
}
func containsCode(s, c string) bool { return len(s) > 0 && (len(c) == 0 || (len(s) >= len(c))) && (indexOf(s, c) >= 0) }
func indexOf(s, sub string) int { for i := 0; i+len(sub) <= len(s); i++ { if s[i:i+len(sub)] == sub { return i } }; return -1 }
```

- [ ] **Step 3: Run it — expect FAIL** (`undefined: renderEmail`)

Run: `go test ./internal/service/ -run TestRenderEmailLocale`

- [ ] **Step 4: Implement `renderEmail` + `normalizeEmailLang`** in `email.go` using `embed.FS` + `text/template` (subject, txt) and `html/template` (html); resolve locale via a supported-set map (reuse the same 8 codes), fallback `en`. Rewrite the four `Send*Email` to accept `lang string`, call `renderEmail`, and pass results to `es.SendEmail`.

- [ ] **Step 5: Update callers** — grep `SendVerificationEmail\|SendEmailChangeVerification\|SendPasswordResetEmail\|Send2FAResetEmail` and add the `lang` arg: pass `derefLang(user.Language)` where a user row exists; pass `""` (⇒ en) for pre-account registration verification.

- [ ] **Step 6: Translate templates** into the other 7 locales (`emailtemplates/<L>/*`), preserving `{{.Code}}`.

- [ ] **Step 7: Run tests + build — expect PASS**

Run: `go test ./internal/service/ && go build ./...`

- [ ] **Step 8: Commit**
```bash
git add internal/service/
git commit -m "feat(i18n): localized transactional emails (8 locales)"
```

---

# WAVE 3 — Guardrail & verification

### Task 18: Extraction config + CI key-parity guardrail

**Files:**
- Create: `client/i18next-parser.config.js`
- Modify: `client/package.json` (script)
- Modify: `.github/workflows/build.yml`

- [ ] **Step 1: `client/i18next-parser.config.js`**
```js
export default {
  locales: ['en'],
  defaultNamespace: 'common',
  input: ['src/**/*.{ts,tsx}'],
  output: 'src/i18n/locales/$LOCALE/$NAMESPACE.json',
  keySeparator: '.',
  namespaceSeparator: ':',
  sort: true,
  keepRemoved: true,
};
```

- [ ] **Step 2: Add scripts** to `client/package.json`:
```json
"i18n:extract": "i18next 'src/**/*.{ts,tsx}' -c i18next-parser.config.js",
"i18n:check": "node scripts/i18n-parity.mjs"
```

- [ ] **Step 3: Parity script `client/scripts/i18n-parity.mjs`** — fails (exit 1) if any non-`en` locale is missing a key present in `en` (deep key set compare across all namespaces). Print the missing keys.

- [ ] **Step 4: Wire into CI** — in `.github/workflows/build.yml`, add a step after the client build: `npm --prefix client run i18n:check`.

- [ ] **Step 5: Run locally — expect PASS** (`npm --prefix client run i18n:check`), then commit.

---

### Task 19: Playwright e2e — language switch + autodetect

**Files:**
- Create: `e2e/language-switch.spec.ts`

- [ ] **Step 1: Write the test** — log in as the test user, go to Settings, select `Deutsch`, assert a known German string is visible and `document.documentElement.lang === 'de'`; reload and assert it persisted; select `Automatic`, set browser locale via context `locale: 'fr'`, assert French appears. Use the existing e2e auth/setup helpers.

- [ ] **Step 2: Run** — `npm run test:e2e` (spins up the compose test stack). Expected: the new spec passes alongside the existing suite.

- [ ] **Step 3: Commit.**

---

### Task 20: Final verification + docs

- [ ] **Step 1: Full client verify** — `npm --prefix client run typecheck && npm --prefix client test && npm --prefix client run build && npm --prefix client run i18n:check`. All green.
- [ ] **Step 2: Full backend verify** — `go build ./... && go test ./...`. All green.
- [ ] **Step 3: Update `docs/i18n.md`** status from "proposal / not yet implemented" to "implemented (see plan 2026-07-19)"; note the deferred backend API-error catalog as the remaining phase.
- [ ] **Step 4: Commit** the doc update.

---

## Self-Review notes

- **Spec coverage:** selector+autodetect (Task 4), 8 locales full UI (Tasks 5–16), `User.language` persistence (Task 3), `format.ts` w/ data-key exclusion (Task 2 + Wave-1 procedure), localized emails (Task 17), CI parity guardrail (Task 18), e2e (Task 19), `<html lang>` sync (Task 1). Backend API-error catalog intentionally absent (deferred per spec §4).
- **Placeholder scan:** the Wave-1/Wave-2 tasks specify procedure + exact files + done-criteria rather than enumerating hundreds of generated keys — this is inherent to a mechanical sweep, not a TODO. Foundation tasks carry complete code.
- **Type consistency:** `normalizeLanguage` (Go), `isSupportedLanguage`/`SUPPORTED_LANGUAGES` (TS), `savePreferences({weight_unit,timezone,language})`, `User.language: string | null`, `renderEmail`/`normalizeEmailLang` are used consistently across tasks.
