# Schautrack Manual Test Checklist

Use this checklist when testing a new release before merging to main.

## Authentication

- [x] Register a new account (open registration mode)
- [x] Register: confirm password field validates on blur (red mismatch, green match)
- [x] Register: submit button disabled until email + both passwords filled and matching
- [ ] Register with invite code (invite-only mode)
- [x] Log in with email/password
- [x] Enable 2FA (TOTP), verify backup codes are shown
- [ ] Log out, log back in with 2FA code
- [ ] Log in using a 2FA backup code
- [ ] Disable 2FA (requires TOTP code or backup code)
- [ ] Reset 2FA via email verification (from login screen)
- [ ] Regenerate backup codes from settings
- [ ] Captcha appears after repeated failed logins
- [ ] Forgot password flow (request reset, receive email, set new password)
- [ ] Email verification on new registration (verify link works)
- [ ] Resend email verification
- [ ] Log out
- [ ] Cannot access protected routes when logged out
- [ ] Delete own account (requires password, 2FA code if enabled)

## Calorie Tracking (Core)

- [ ] Add a calorie entry with name and amount
- [ ] Add entry with only macros (no name), verify it saves
- [ ] Math expressions in calorie/macro inputs (e.g. `200+150`, `3*120`)
- [ ] Edit an existing entry inline (tap name to edit name, tap macro pill to edit value)
- [ ] Verify entry rows display as cards with colored macro pills
- [ ] Delete an entry
- [ ] Verify daily total updates correctly
- [ ] Verify dot/status colors reflect goal progress (green/yellow/red/grey)
- [ ] Navigate between dates, verify entries are date-correct
- [ ] Change entry date via date picker in entry form
- [ ] Timeline/overview shows correct history across date range
- [ ] Click a timeline dot to navigate to that day's entries
- [ ] Custom date range picker (start/end dates + apply)
- [ ] Click a share card to switch viewed user

## Macros

- [ ] Enable/disable individual macros (fat, carbs, fiber, sugar, protein)
- [ ] Disable calories tracking entirely, verify calorie input disappears
- [ ] Set macro goals and modes (target vs limit)
- [ ] Set goal threshold percentage, verify over-threshold turns red
- [ ] Enable auto-calc calories (requires protein + carbs + fat), verify calorie field is read-only and computed
- [ ] Add entry with macro values, verify they display correctly
- [ ] Verify macro totals for the day (TodayPanel chips with progress bars)
- [ ] Macro columns visible in entry list when enabled
- [ ] Verify macro status colors (green/yellow/red) match target vs limit modes

## Weight Tracking

- [ ] Add a weight entry via the weight row
- [ ] Verify only one weight entry per day (overwrite behavior)
- [ ] Delete a weight entry
- [ ] Switch weight unit (kg/lbs), verify display

## AI Photo Estimation

- [ ] Upload a food photo, verify AI returns calorie + macro estimate
- [ ] Test camera capture on mobile
- [ ] Verify AI button shows when global key is configured (no personal key needed)
- [ ] Verify daily usage counter decrements and button disables at limit
- [ ] Verify personal AI key + custom endpoint works from settings
- [ ] AI result pre-fills entry form (name, calories, macros)

## Barcode Scanning

- [ ] Scan a barcode, verify product lookup from OpenFoodFacts
- [ ] Barcode result pre-fills entry form (name, calories, macros)
- [ ] Verify barcode button hidden when admin disables it
- [ ] Verify barcode rate limiting (30/min)

## Todos

- [ ] Enable todos in settings
- [ ] Create a new todo item
- [ ] Mark a todo as complete
- [ ] Delete a todo
- [ ] Edit todo name, schedule, and time from manage view
- [ ] Create todo with "daily" schedule, verify it shows every day
- [ ] Create todo with "specific weekdays" schedule, verify it only shows on those days
- [ ] Set time of day on a todo (smart input: typing "930" shows "09:30"), verify it displays
- [ ] Verify streak counter increments on consecutive completions
- [ ] Verify streak resets after a missed day
- [ ] Verify todos persist across days
- [ ] Verify linked user can see your todos

## Daily Notes

- [ ] Enable notes in settings
- [ ] Write a note for today, verify autosave (1s debounce)
- [ ] Verify "Saving..." / "Saved" indicator works
- [ ] Navigate to another date, verify note is date-specific
- [ ] Clear note content, verify it gets deleted
- [ ] Verify character limit (10,000) enforced
- [ ] Verify linked user can see your notes (read-only)
- [ ] Disable notes, verify editor disappears

## Account Linking

- [ ] Send a link request to another user
- [ ] Accept/decline a link request
- [ ] Set a custom label on a linked user (click name to edit)
- [ ] View linked user's entries (read-only, cannot edit/delete)
- [ ] View linked user's weight, todos, and notes
- [ ] Verify entry times show in CREATOR's timezone (when they ate)
- [ ] Verify linked user's share card shows their dot history
- [ ] Remove a link
- [ ] Verify max 3 links enforced

## Timezone Handling

- [ ] Change timezone in settings
- [ ] Add entries near midnight, verify they land on correct date
- [ ] View linked user's entries across timezone boundaries

## Settings

- [ ] Change daily calorie goal
- [ ] Change display name (via account linking label)
- [ ] Change email (triggers verification of new address)
- [ ] Cancel pending email change
- [ ] Change password
- [ ] Set/clear personal AI key and endpoint
- [ ] Change AI provider (OpenAI / Claude / Ollama), verify AI still works
- [ ] Custom AI model override
- [ ] Export data (JSON) — includes entries, weights, settings
- [ ] Import data (JSON) — verify entries and weights restored
- [ ] Toggle notes enabled/disabled
- [ ] Toggle todos enabled/disabled
- [ ] Preferences: change weight unit (autosaves)
- [ ] Preferences: change timezone (autosaves)
- [ ] Verify autosave indicators across all settings sections
- [ ] Verify no spurious "Saved" indicator on initial settings load
- [ ] Verify all action buttons are full-width at card bottom
- [ ] Data card: Export button works, Import disabled until file selected

## Real-time (SSE)

- [ ] Open two browser tabs, add entry in one, verify it appears in the other
- [ ] Verify linked user updates propagate in real-time
- [ ] Verify todo/note/weight changes propagate in real-time

## Share Card

- [ ] Generate a share card for the day
- [ ] Verify it renders correctly with current entries
- [ ] Dots wrap correctly on narrow screens (row gap, spacing)

## Admin Panel

- [ ] Access admin panel as admin user
- [ ] Cannot access admin routes as non-admin
- [ ] Toggle registration open/closed
- [ ] Toggle barcode feature on/off
- [ ] Configure global AI settings (provider, model, key, daily limit)
- [ ] Configure legal settings (support email, imprint address/email, enable legal)
- [ ] View/manage users
- [ ] Delete a user (verify cascade deletes all their data)
- [ ] Cannot delete yourself from admin panel
- [ ] Create invite code (with and without email)
- [ ] Verify invite email is sent when SMTP is configured
- [ ] Delete unused invite code
- [ ] Cannot delete already-used invite code
- [ ] View invite list (used/unused/expired)
- [ ] Settings locked when controlled by env var (shows disabled)

## Responsive / Mobile

- [ ] Dashboard usable on mobile viewport (no horizontal scroll)
- [ ] Calorie input shows numeric keypad (`inputmode="tel"`)
- [ ] Navigation and modals work on small screens
- [ ] AI photo modal works fullscreen on mobile
- [ ] Entry list card rows and macro pills readable on mobile
- [ ] Active nav item highlighted (cyan tint + border)
- [ ] Note editor usable on mobile

## Security

- [ ] Verify CSRF protection (reject forged requests)
- [ ] Cannot edit/delete another user's entries
- [ ] Cannot access another user's data without an active link
- [ ] Rate limiting on login, forgot password, and AI endpoints
- [ ] Session httpOnly / secure cookies
- [ ] Verify session expires correctly

## SEO / Public

- [ ] `/robots.txt` returns correct content (respects `robotsIndex` config)
- [ ] `/sitemap.xml` returns valid sitemap
- [ ] Landing page renders for logged-out visitors
- [ ] Landing page shows feature cards and GitHub/Play Store links
- [ ] SPA routing works (direct URL to `/settings`, `/login`, etc. loads correctly)

## Legal Pages

- [ ] Imprint page loads (when enabled)
- [ ] Imprint address/email render as SVG (anti-scraping)
- [ ] Privacy policy page loads (when enabled)
- [ ] Legal pages hidden when `enable_legal` is off

## Go Backend Migration

- [ ] Existing users are prompted to re-login (session cookie changed from `connect.sid` to `schautrack.sid`)
- [ ] Users with old bcrypt password hashes can still log in (legacy hash support)
- [ ] After login with bcrypt hash, password is re-hashed to argon2id on next change
- [ ] All API responses match expected JSON shape (no regressions from Node.js)
- [ ] Date/time formats in API responses are consistent with what the React frontend expects
- [ ] Error responses use correct HTTP status codes and JSON error format
- [ ] CSRF token generation and validation works (Go implementation matches Node.js behavior)
- [ ] Session expiry and cleanup behaves correctly (Go session store)
- [ ] File upload (AI photo) works with Go multipart handling
- [ ] Database migrations in Go (`ensureXxxSchema()`) run cleanly on an existing Node.js-era database
- [ ] No leftover Node.js `src/` code is served or referenced at runtime

## Infrastructure

- [ ] `GET /api/health` returns 200 with DB connected and version
- [ ] App starts cleanly with `docker compose up`
- [ ] Schema migrations run on fresh DB without errors
- [ ] Existing DB migrates cleanly (no data loss)
- [ ] Expired tokens get cleaned up (runs every 15 min)
- [ ] Graceful shutdown (SIGTERM) completes without errors
- [ ] Static assets served with correct cache headers (`immutable` for hashed assets)
- [ ] Helm chart deploys successfully to staging
- [ ] Staging accessible at staging.schautrack.com
- [ ] Production deploy via ArgoCD after staging verified
- [ ] Go unit tests pass (`go test ./...`)
- [ ] TypeScript compiles cleanly (`npx tsc --noEmit` in `client/`)
- [ ] Vite production build succeeds (`npx vite build` in `client/`)
- [ ] Playwright e2e tests pass
