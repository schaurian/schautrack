# Mobile-native redesign — design

**Date:** 2026-07-19
**Status:** approved (brainstormed with visual mockups; user delegated final calls)
**Scope:** whole client app (Dashboard, Plan, Settings, Admin, auth/guest pages)

## 1. Problem

On Android (the schautrack-android WebView wrapper and mobile browsers) the UI wastes
a large share of the viewport on box chrome: every section is a bordered card
(`border-2`, `p-4`/`p-6`), stat tiles nest cards-in-cards, and entries are cards with
pill badges inside. On a 360 px-wide phone the padding/border stack means only the
Today panel and part of the entry form fit above the fold, and the app reads as a
shrunken website rather than an app. The overall look should also get a modern
refresh — on desktop too, with both sharing one visual language.

## 2. Direction (decided in brainstorming)

- **Mobile (<1024 px): native-app feel.** No top nav. Edge-to-edge content, macro
  progress rings, flat divider-separated lists, bottom tab bar, floating **+** button
  opening a bottom sheet with the entry form.
- **Desktop (≥1024 px): D2 sidebar.** Persistent left sidebar (logo, nav, user chip),
  content in a centered column so desktop mirrors the phone layout. Chosen over
  top-nav after mockup comparison.
- **Flat everywhere.** Nested boxes are removed app-wide; hierarchy comes from
  whitespace, small uppercase section labels, and hairline dividers. The dark palette,
  macro colors, and background gradients stay — this is de-boxing + modernization,
  not a re-theme.

## 3. Navigation & app shell

### Authenticated shell
- **Tabs/sections:** Today (`/dashboard`), Plan (`/plan`), Settings (`/settings`),
  plus Admin (`/admin`) only when `isAdmin`.
- **Mobile:** bottom tab bar, fixed, 3–4 items, active item tinted primary. The
  pending-link-requests badge moves from the old Settings nav link onto the Settings
  tab icon. FAB and sheet render above it. `env(safe-area-inset-bottom)` padding for
  Android gesture nav.
- **Desktop:** left sidebar (~220 px): logo top, vertical nav (same items + badge),
  user chip (initial + name) at the bottom which links to Settings. Logout — today a
  Header button — **moves to a Settings row** (see §4 Settings), since the authed
  shell has no header anymore; desktop and mobile share that placement. Content area
  centers a `max-w-2xl` column.
- **Layout component** switches shell by breakpoint (`lg:`). The current `Header.tsx`
  survives only for guest pages.

### Guest/auth pages (Landing, Login, Register, Forgot/Reset, Verify, Legal)
- Keep a minimal top bar (logo + Login/Register links) and footer.
- Forms restyled with the shared flat tokens (same inputs/buttons, no card boxes;
  a single subtle surface panel on desktop is acceptable for form focus).

## 4. Screens

### Today (Dashboard)
Order top-to-bottom: date header → rings → timeline → meals → weight → todos → notes
→ plan link. All sections flat, labeled with small uppercase headers.

- **Date header:** page title ("Today" or the selected date) + tappable date control
  (existing selectedDate behavior; "▾" opens the native date input).
- **Rings (replaces TodayPanel stat tiles):** one ring per tracked metric — kcal
  (when `caloriesEnabled`) + each enabled macro. Ring = conic-gradient progress
  toward goal; center shows current value, goal beneath; label below in the macro's
  color. Ring track color encodes the existing `MacroStatus` (success green / warning
  amber / danger red); metrics without goals render a neutral full track with the
  value. Up to 4 rings in one row; 5–6 wrap to a second row (grid, centered). The
  "no nutrients tracked" empty state keeps its settings link.
- **Timeline:** dot grid becomes edge-to-edge (no card). Per-user sections stay
  (ShareCard flattened to a label row + dots — keeps selection, label editing, and
  the link-sharing e2e surface intact); the range preset picker collapses into a
  compact "N days ▾" popover on the section label row. DayDot behavior (select day,
  today ring, status colors) is unchanged.
- **Meals (EntryList):** flat rows with hairline dividers — name + time on the first
  line, compact colored macro values (`180 kcal · P5 · C22 · F9` style) on the second.
  Existing interactions are preserved exactly: tap name/value to edit inline
  (MacroPill editing collapses into the compact value form), delete with undo toast,
  save-as-quick-add icon. Touch targets ≥44 px row height.
- **Weight (WeightRow):** flat row: value + unit, tap-to-edit as today.
- **Todos (TodoList):** flat checklist rows, existing add/complete/delete logic.
- **Notes (NoteEditor):** flat section, textarea styled to the flat tokens.
- **Plan (PlanCard):** compact flat row — current → target, trend chip, thin progress
  bar — linking to `/plan`.
- **Friend views:** when viewing a linked user (`!canEdit`), FAB/quick-add are hidden
  (no entry creation), rows are read-only, and only shared categories render —
  identical to current logic, restyled.

### Adding food (EntryForm)
- **One form component, two presentations:**
  - **Mobile:** FAB (**+**, gradient, bottom-right above the tab bar) opens a bottom
    **Sheet** containing the full form: name, qty, kcal (auto-calc aware), enabled
    macros, date, AI photo, barcode scan, saved-foods chip row. Track submits, closes
    the sheet, toasts.
  - **Desktop:** the full form stays inline (flat, de-boxed). (Originally a
    collapse-on-focus quick-add; kept fully visible to avoid churning the 8
    entry-form e2e specs and to save a click.)
- SavedFoodsRow chips move inside the sheet on mobile; on desktop they stay under the
  quick-add row.
- AIPhotoModal, BarcodeScanModal, SavedFoodsModal keep their current overlay
  presentation for now; converting them to the Sheet primitive is a follow-up
  once the shell has landed.

### Plan
- GoalForm/MetricsForm card stack → flat labeled sections in the centered column;
  warnings become inline flat alerts.

### Settings
- 14 stacked cards → grouped flat list (native settings style): group label, rows
  with divider, controls right-aligned; each existing settings component keeps its
  logic and becomes a group. Order preserved.
- New **Logout row** (account group, top) using the Header's existing logout logic
  (network logout → clear client state → navigate to `/login`).
- Danger zone (delete account) keeps a red accent but no box.

### Admin
- Tables/lists flattened to divider rows; same data and actions.

## 5. New UI primitives

| Primitive | Purpose |
|---|---|
| `BottomNav` | Mobile tab bar (nav items, badge, safe-area) |
| `Sidebar` | Desktop nav rail |
| `Fab` | Floating action button |
| `Sheet` | Bottom sheet on mobile / centered dialog on desktop: backdrop, drag-handle visual, focus trap, `Escape`/backdrop close, scroll lock, `prefers-reduced-motion`-aware slide-up |
| `Ring` | Conic-gradient progress ring (value, goal, label, status color) |
| `SectionLabel` | Small uppercase section header row (label + optional right-side control) |
| `Row` (pattern, not necessarily a component) | Flat list row: min-height 44 px, hairline divider |

`Card.tsx` remains for the few places a contained surface is still right (auth forms
on desktop) but loses its default heavy padding/border; most usages are replaced.

## 6. Design tokens & Android polish

- Radii: interactive elements 12–16 px, sheet 20 px top corners.
- Borders: `--color-border` hairlines only (dividers, input outlines); no `border-2`.
- Dividers: a dedicated dimmer `--color-divider` so lists don't look ruled.
- Typography: page title ~22 px/800; section labels ~11 px uppercase tracking-wide;
  body unchanged.
- `index.html`: `viewport-fit=cover`, `theme-color` `#070d1a` so the WebView status
  bar blends.
- Tap: `-webkit-tap-highlight-color: transparent`, `touch-action: manipulation` on
  interactive elements; `overscroll-behavior-y: none` on the app shell.
- Respect `prefers-reduced-motion` (already global) for sheet/FAB animations.

## 7. i18n

The client is fully translated (8 locales, `react-i18next`, CI key-parity gate).
Every new string goes through `t()`; after UI work, run `npm run i18n:extract` and
translate new keys in **all 8** locale files; `npm run i18n:check` must pass.
Tab labels reuse existing nav strings where possible.

## 8. Out of scope

- No Go/backend changes (JSON API untouched).
- No new features, no data-model changes, no PWA/service-worker work.
- No light theme; no re-theming of colors.
- schautrack-android wrapper unchanged (it just renders the web UI).

## 9. Testing & verification

- **Unit:** client Vitest suite stays green; add tests for `Sheet` (open/close/focus)
  and `Ring` (progress/status mapping) where practical.
- **E2E:** Playwright suite must pass. Structural selectors that break (nav links →
  tabs/sidebar, entry form → sheet on mobile viewport) are updated with the redesign;
  Playwright projects run desktop-sized, so the inline quick-add path keeps most specs
  valid, with a mobile-viewport spec added for tab bar + sheet add-flow.
- **Visual:** manual verification at 360×800 (Android reference) and ≥1280 desktop
  via vite dev/compose against real flows: login → track entry (sheet + inline) →
  edit/delete → timeline day switch → friend view → settings → plan → admin.
- **CI gates:** client build, `i18n:check`, `go test ./...` (untouched but must stay
  green), lint.

## 10. Delivery

- Branch `mobile-native-redesign` (worktree), based on `origin/staging`; PR into
  `staging` → staging Helm channel → `schautrack-staging` for live verification,
  following the repo's conventional-commit versioning.
- Implementation phases (each leaves the app shippable):
  1. **Foundation:** tokens, primitives (Sheet, Ring, BottomNav, Sidebar, Fab,
     SectionLabel), new Layout shell, guest pages intact.
  2. **Today screen:** rings, flat timeline, flat lists, FAB + sheet entry flow.
  3. **Secondary pages:** Settings, Plan, Admin, auth/legal restyle.
  4. **Polish & verification:** i18n extraction/translation, e2e updates, manual
     mobile/desktop pass.
