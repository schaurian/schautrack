# Schautrack Manual Test Checklist

Use this checklist when testing a new release before merging to main.
Items marked [A] are covered by automated E2E tests (`npm run test:e2e`).

## Authentication

- [x] [A] Register a new account (open registration mode)
- [x] [A] Register: confirm password field validates on blur (red mismatch, green match)
- [x] [A] Register: submit button disabled until email + both passwords filled and matching
- [x] [A] Register with invite code (invite-only mode)
- [x] [A] Log in with email/password
- [x] [A] Enable 2FA (TOTP), verify backup codes are shown
- [x] [A] Log out, log back in with 2FA code
- [x] [A] Log in using a 2FA backup code
- [x] [A] Disable 2FA (requires TOTP code or backup code)
- [x] [A] Reset 2FA via email verification (from login screen)
- [x] [A] Regenerate backup codes from settings
- [x] [A] Captcha appears after repeated failed logins
- [x] [A] Forgot password flow (request reset, receive email, set new password)
- [x] [A] Email verification on new registration (verify link works)
- [x] [A] Resend email verification
- [x] [A] Log out
- [x] [A] Cannot access protected routes when logged out
- [x] [A] Delete own account (requires password, 2FA code if enabled)

## Calorie Tracking (Core)

- [x] [A] Add a calorie entry with name and amount
- [x] [A] Add entry with only macros (no name), verify it saves
- [x] [A] Math expressions in calorie/macro inputs (e.g. `200+150`, `3*120`)
- [x] [A] Edit an existing entry inline (tap name to edit name, tap macro pill to edit value)
- [x] [A] Verify entry rows display as cards with colored macro pills
- [x] [A] Delete an entry
- [x] [A] Verify daily total updates correctly
- [x] [A] Verify dot/status colors reflect goal progress (green/yellow/red/grey)
- [x] [A] Navigate between dates, verify entries are date-correct
- [x] [A] Change entry date via date picker in entry form
- [x] [A] Timeline/overview shows correct history across date range
- [x] [A] Click a timeline dot to navigate to that day's entries
- [x] [A] Custom date range picker (start/end dates + apply)
- [x] [A] Click a share card to switch viewed user

## Macros

- [x] [A] Enable/disable individual macros (fat, carbs, fiber, sugar, protein)
- [x] [A] Disable calories tracking entirely, verify calorie input disappears
- [x] [A] Set macro goals and modes (target vs limit)
- [x] [A] Set goal threshold percentage, verify over-threshold turns red
- [x] [A] Enable auto-calc calories (requires protein + carbs + fat), verify calorie field is read-only and computed
- [x] [A] Add entry with macro values, verify they display correctly
- [x] [A] Verify macro totals for the day (TodayPanel chips with progress bars)
- [x] [A] Macro columns visible in entry list when enabled
- [x] [A] Verify macro status colors (green/yellow/red) match target vs limit modes

## Weight Tracking

- [x] [A] Add a weight entry via the weight row
- [x] [A] Verify only one weight entry per day (overwrite behavior)
- [x] [A] Delete a weight entry
- [x] [A] Switch weight unit (kg/lbs), verify display

## AI Photo Estimation

- [ ] Upload a food photo, verify AI returns calorie + macro estimate (requires real AI key)
- [ ] Test camera capture on mobile (hardware dependent)
- [x] [A] Verify AI button shows when global key is configured (no personal key needed)
- [x] [A] Verify daily usage counter decrements and button disables at limit
- [x] [A] Verify personal AI key + custom endpoint works from settings
- [x] [A] AI result pre-fills entry form (name, calories, macros)

## Barcode Scanning

- [ ] Scan a barcode, verify product lookup from OpenFoodFacts (camera dependent)
- [x] [A] Barcode result pre-fills entry form (name, calories, macros)
- [x] [A] Verify barcode button hidden when admin disables it
- [ ] Verify barcode rate limiting (30/min)

## Todos

- [x] [A] Enable todos in settings
- [x] [A] Create a new todo item
- [x] [A] Mark a todo as complete
- [x] [A] Delete a todo
- [x] [A] Edit todo name, schedule, and time from manage view
- [x] [A] Create todo with "daily" schedule, verify it shows every day
- [x] [A] Create todo with "specific weekdays" schedule, verify it only shows on those days
- [x] [A] Set time of day on a todo (smart input: typing "930" shows "09:30"), verify it displays
- [x] [A] Verify streak counter increments on consecutive completions
- [x] [A] Verify streak resets after a missed day
- [x] [A] Verify todos persist across days
- [x] [A] Verify linked user can see your todos

## Daily Notes

- [x] [A] Enable notes in settings
- [x] [A] Write a note for today, verify autosave (1s debounce)
- [x] [A] Verify "Saving..." / "Saved" indicator works
- [x] [A] Navigate to another date, verify note is date-specific
- [x] [A] Clear note content, verify it gets deleted
- [x] [A] Verify character limit (10,000) enforced
- [x] [A] Verify linked user can see your notes (read-only)
- [x] [A] Disable notes, verify editor disappears

## Account Linking

- [x] [A] Send a link request to another user
- [x] [A] Accept/decline a link request
- [x] [A] Set a custom label on a linked user (click name to edit)
- [x] [A] View linked user's entries (read-only, cannot edit/delete)
- [x] [A] View linked user's weight, todos, and notes
- [x] [A] Verify entry times show in CREATOR's timezone (when they ate)
- [x] [A] Verify linked user's share card shows their dot history
- [x] [A] Remove a link
- [x] [A] Verify max 3 links enforced

## Timezone Handling

- [x] [A] Change timezone in settings
- [x] [A] Add entries near midnight, verify they land on correct date
- [x] [A] View linked user's entries across timezone boundaries

## Settings

- [x] [A] Change daily calorie goal
- [x] [A] Change display name (via account linking label)
- [x] [A] Change email (triggers verification of new address)
- [x] [A] Cancel pending email change
- [x] [A] Change password
- [x] [A] Set/clear personal AI key and endpoint
- [ ] Change AI provider (OpenAI / Claude / Ollama), verify AI still works (requires real keys)
- [ ] Custom AI model override
- [x] [A] Export data (JSON) — includes entries, weights, settings
- [x] [A] Import data (JSON) — verify entries and weights restored
- [x] [A] Toggle notes enabled/disabled
- [x] [A] Toggle todos enabled/disabled
- [x] [A] Preferences: change weight unit (autosaves)
- [x] [A] Preferences: change timezone (autosaves)
- [x] [A] Verify autosave indicators across all settings sections
- [x] [A] Verify no spurious "Saved" indicator on initial settings load
- [ ] Verify all action buttons are full-width at card bottom (visual)
- [x] [A] Data card: Export button works, Import disabled until file selected

## Real-time (SSE)

- [x] [A] Open two browser tabs, add entry in one, verify it appears in the other
- [x] [A] Verify linked user updates propagate in real-time
- [x] [A] Verify todo/note/weight changes propagate in real-time

## Share Card

- [x] [A] Verify share card renders with dots for own user
- [x] [A] Verify dots update after adding entries
- [ ] Dots wrap correctly on narrow screens (row gap, spacing) (visual)

## Admin Panel

- [x] [A] Access admin panel as admin user
- [x] [A] Cannot access admin routes as non-admin
- [x] [A] Toggle registration open/closed
- [x] [A] Toggle barcode feature on/off
- [x] [A] Configure global AI settings (provider, model, key, daily limit)
- [x] [A] Configure legal settings (support email, imprint address/email, enable legal)
- [x] [A] View/manage users
- [x] [A] Delete a user (verify cascade deletes all their data)
- [x] [A] Cannot delete yourself from admin panel
- [x] [A] Create invite code (with and without email)
- [x] [A] Verify invite email is sent when SMTP is configured
- [x] [A] Delete unused invite code
- [x] [A] Cannot delete already-used invite code
- [x] [A] View invite list (used/unused/expired)
- [x] [A] Settings locked when controlled by env var (shows disabled)

## Responsive / Mobile

- [x] [A] Dashboard usable on mobile viewport (no horizontal scroll)
- [x] [A] Calorie input shows numeric keypad (`inputmode="tel"`)
- [x] [A] Navigation and modals work on small screens
- [ ] AI photo modal works fullscreen on mobile (hardware dependent)
- [ ] Entry list card rows and macro pills readable on mobile (visual)
- [x] [A] Active nav item highlighted (cyan tint + border)
- [x] [A] Note editor usable on mobile

## Security

- [x] [A] Verify CSRF protection (reject forged requests)
- [x] [A] Cannot edit/delete another user's entries
- [x] [A] Cannot access another user's data without an active link
- [ ] Rate limiting on login, forgot password, and AI endpoints
- [x] [A] Session httpOnly / secure cookies
- [x] [A] Verify session expires correctly

## SEO / Public

- [x] [A] `/robots.txt` returns correct content (respects `robotsIndex` config)
- [x] [A] `/sitemap.xml` returns valid sitemap
- [x] [A] Landing page renders for logged-out visitors
- [x] [A] Landing page shows feature cards and GitHub/Play Store links
- [x] [A] SPA routing works (direct URL to `/settings`, `/login`, etc. loads correctly)

## Legal Pages

- [x] [A] Imprint page loads (when enabled)
- [x] [A] Imprint address/email render as SVG (anti-scraping)
- [x] [A] Privacy policy page loads (when enabled)
- [x] [A] Legal pages hidden when `enable_legal` is off

## Go Backend Migration

- [x] [A] Existing users are prompted to re-login (session cookie changed from `connect.sid` to `schautrack.sid`)
- [x] [A] Users with old bcrypt password hashes can still log in (legacy hash support)
- [x] [A] After login with bcrypt hash, password is re-hashed to argon2id on next change
- [x] [A] All API responses match expected JSON shape (no regressions from Node.js)
- [x] [A] Date/time formats in API responses are consistent with what the React frontend expects
- [x] [A] Error responses use correct HTTP status codes and JSON error format
- [x] [A] CSRF token generation and validation works (Go implementation matches Node.js behavior)
- [x] [A] Session expiry and cleanup behaves correctly (Go session store)
- [ ] File upload (AI photo) works with Go multipart handling (requires real AI key)
- [x] [A] Database migrations in Go (`ensureXxxSchema()`) run cleanly on an existing Node.js-era database
- [x] [A] No leftover Node.js `src/` code is served or referenced at runtime

## Infrastructure

- [x] [A] `GET /api/health` returns 200 with DB connected and version
- [x] [A] App starts cleanly with `docker compose up`
- [x] [A] Schema migrations run on fresh DB without errors
- [ ] Existing DB migrates cleanly (no data loss)
- [x] [A] Expired tokens get cleaned up (runs every 15 min)
- [x] [A] Graceful shutdown (SIGTERM) completes without errors
- [x] [A] Static assets served with correct cache headers (`immutable` for hashed assets)
- [ ] Helm chart deploys successfully to staging
- [ ] Staging accessible at staging.schautrack.com
- [ ] Production deploy via ArgoCD after staging verified
- [x] [A] Go unit tests pass (`go test ./...`)
- [x] [A] TypeScript compiles cleanly (`npx tsc --noEmit` in `client/`)
- [x] [A] Vite production build succeeds (`npx vite build` in `client/`)
- [x] [A] Playwright e2e tests pass
