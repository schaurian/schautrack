# Schautrack Manual Test Checklist

Use this checklist when testing a new release before merging to main.

## Authentication

- [x] Register a new account
- [x] Log in with email/password
- [x] Enable 2FA (TOTP), log out, log back in with 2FA code
- [x] Disable 2FA
- [x] Log out

## Calorie Tracking (Core)

- [x] Add a calorie entry with name and amount
- [x] Edit an existing entry
- [x] Delete an entry
- [x] Verify daily total updates correctly
- [x] Verify dot/status colors reflect goal progress (green/yellow/red/grey)

## Macros

- [x] Enable/disable individual macros (fat, carbs, fiber, sugar, protein)
- [x] Set macro goals and modes (target vs limit)
- [x] Add entry with macro values, verify they display correctly
- [x] Verify macro totals for the day

## Weight Tracking

- [x] Add a weight entry
- [x] Verify only one weight entry per day (overwrite behavior)
- [x] Switch weight unit (kg/lbs), verify display

## AI Photo Estimation

- [x] Upload a food photo, verify AI returns calorie estimate
- [x] Test with each provider if configured (OpenAI, Claude, Ollama)
- [x] Verify rate limiting on global key works

## Account Linking

- [x] Send a link request to another user
- [x] Accept/decline a link request
- [x] View linked user's entries (read-only)
- [x] Verify timestamps show in YOUR timezone, not theirs
- [x] Remove a link
- [x] Verify max 3 links enforced

## Timezone Handling

- [x] Change timezone in settings
- [x] Add entries near midnight, verify they land on correct date
- [x] View linked user's entries across timezone boundaries

## Settings

- [x] Change daily calorie goal
- [x] Change display name / email
- [x] Change password
- [x] Set/clear personal AI key and endpoint
- [x] Export data (JSON)
- [x] Import data

## Data Export/Import

- [x] Export full data as JSON
- [x] Import an export file into a fresh account
- [x] Verify all fields round-trip correctly (macros_enabled, macro_goals, entries, etc.)

## Real-time (SSE)

- [x] Open two browser tabs, add entry in one, verify it appears in the other
- [x] Verify linked user updates propagate in real-time

## Responsive / Mobile

- [x] Dashboard usable on mobile viewport
- [x] Calorie input shows numeric keypad (`inputmode="tel"`)
- [x] Navigation and modals work on small screens

## Security

- [x] Verify CSRF protection (reject forged requests)
- [x] Verify session expires / httpOnly cookies
- [x] Cannot edit/delete another user's entries
- [x] Cannot access admin routes as non-admin

## Infrastructure

- [x] `GET /api/health` returns 200 with DB connected
- [x] App starts cleanly with `docker compose up`
- [x] Schema migrations run on fresh DB without errors
