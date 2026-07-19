# Granular Link Sharing — Design Spec

**Date:** 2026-07-19
**Branch:** `granular-link-sharing` (off `staging`)
**Status:** Approved to implement (Option A confirmed by user)

## 1. Problem & Goal

Schautrack lets two users **link accounts** to see each other's data. Today a link
is **all-or-nothing and symmetric**: once accepted, each linked user can view the
*other's* nutrition (calories/macros), weight, todos, **and** daily notes by
switching to their card on the dashboard (`?user=<id>` on the link-aware GET
endpoints). Writes always target the logged-in user, so viewing is already
**read-only** — but there is **no way to choose what you expose**. Linking to a
friend to compare nutrition also hands them your private daily notes and todos.

This feature adds **per-friend, per-category, opt-in sharing**. For each person you
are linked with, you independently choose which of your four data categories they
may see: **Nutrition**, **Weight**, **Todos**, **Daily notes**. Sharing is
**directional** (what you share with them is independent of what they share with
you) and stays **read-only** (unchanged). Everything defaults **off**, including
existing links — a link by itself now grants **nothing** until you tick a box.

It ships to **all schautrack users** (a product feature, not a one-off).

## 2. Decisions (locked)

| Decision | Choice |
|---|---|
| Granularity | **Per category** — four toggles: nutrition, weight, todos, notes. Not per-individual-item. |
| Scope | **Per linked friend** — toggles live next to each link; independent per friend. |
| Direction | **Directional** — your outgoing shares are separate from the friend's. Mirrors the existing `requester_label`/`target_label` split. |
| Categories covered | **All four** are toggleable (nutrition & weight included, not just the newly-private todos/notes). |
| Default (new **and** existing links) | **Everything OFF.** Existing links go dark until the owner opts in. Zero data migration — absent JSONB key = off. |
| Write access | **Unchanged** — always read-only for the other user. Writes target `GetCurrentUser`. |
| Storage | **Option A** — two JSONB share-maps on `account_links`: `requester_shares`, `target_shares`. |
| Enforcement | **Category-aware `RequireLinkAuth(pool, category)`** on friend-view reads; `Dashboard` handler gates nutrition dots + emits per-view `shares`. |

**Alternatives considered & rejected:** 8 boolean columns (wide; every future
category is a migration); a normalized `link_shares` table (adds a join to every
auth check and the dashboard build for only 4 fixed categories — YAGNI);
per-individual-item sharing (awkward for per-date notes; user chose per-category);
keeping nutrition/weight always-shared (user chose all-toggleable, fully
privacy-first).

## 3. Data Model

### 3.1 Category keys (single source of truth)

`internal/service/links.go` — canonical constants + set, imported by middleware and handlers:

```go
const (
    ShareNutrition = "nutrition"
    ShareWeight    = "weight"
    ShareTodos     = "todos"
    ShareNotes     = "notes"
)
var ShareCategories = []string{ShareNutrition, ShareWeight, ShareTodos, ShareNotes}
```

### 3.2 Share-maps — columns on `account_links`

Extend the **existing** `ensureAccountLinksSchema` (in `internal/database/migrations.go`),
mirroring exactly how `requester_label`/`target_label` were added — idempotent,
no new migration function:

```sql
ALTER TABLE account_links
    ADD COLUMN IF NOT EXISTS requester_shares JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS target_shares    JSONB NOT NULL DEFAULT '{}'::jsonb;
```

- Each map is like `{"nutrition":true,"weight":false,"todos":true,"notes":false}`.
- **Missing key ⇒ false ⇒ not shared.** Existing rows get `'{}'` ⇒ all off. This is
  the entire "existing links go dark" mechanism — no `UPDATE` backfill needed.
- **Direction:** a user's *outgoing* shares live in `requester_shares` when they are
  `requester_id`, else `target_shares`. Same convention as the label columns.

## 4. Backend

Conventions from the codebase: `middleware.RequireLogin` on all; `session.CsrfProtection`
on mutations; `JSON`/`ErrorJSON` helpers; `sse.Broker` broadcast on dashboard-visible change.

### 4.1 Category-aware link auth (`internal/middleware/links.go`)

Change the signature `RequireLinkAuth(pool)` → **`RequireLinkAuth(pool, category string)`**.
Behaviour:

- **Self-view** (`?user` absent or equals current user): unchanged, always allowed.
- **Friend-view**: replace the current "does an accepted link exist?" `EXISTS` query
  with a single query that also reads the **sharer's** (target's) map for `category`:

  ```sql
  SELECT COALESCE(
      (CASE WHEN requester_id = $2 THEN requester_shares ELSE target_shares END ->> $3)::boolean,
      false)
  FROM account_links
  WHERE status = 'accepted'
    AND ((requester_id = $1 AND target_id = $2) OR (requester_id = $2 AND target_id = $1))
  ```

  `$1` = current user (viewer), `$2` = target user (sharer), `$3` = category. No row
  (not linked) → `false`. Row present but key false/absent → `false`. On `false` →
  **403** (same JSON body as today). On `true` → proceed, populating
  `targetUser`/`targetUserID` in context as it does now.

Wire the category per existing route (see 4.3). This keeps enforcement in one place
and defends every friend-view endpoint uniformly.

### 4.2 Set-shares endpoint (`internal/handler/settings.go`, `LinksHandler`)

New `POST /links/{id}/shares` — mirrors `LinkLabel` (which already scopes to the
caller's own links and picks the right direction via `CASE`):

- Body: `{"nutrition":bool,"weight":bool,"todos":bool,"notes":bool}` (a full map;
  client always sends all four). Sanitize to only the known keys.
- Update **only the caller's** direction:

  ```sql
  UPDATE account_links
  SET requester_shares = CASE WHEN requester_id = $3 THEN $1 ELSE requester_shares END,
      target_shares    = CASE WHEN target_id    = $3 THEN $1 ELSE target_shares    END,
      updated_at = NOW()
  WHERE id = $2 AND status = 'accepted' AND ($3 = requester_id OR $3 = target_id)
  RETURNING CASE WHEN requester_id = $3 THEN requester_shares ELSE target_shares END
  ```

  `$1` = new map (JSONB), `$2` = linkID, `$3` = current user. No row → **404** (as
  `LinkLabel` does). Return the saved map: `{"ok":true,"shares":{...}}`.
- Broadcast `BroadcastLinkSharesChange(linkID, user.ID)` (new `sse.Broker` method,
  analog of `BroadcastLinkLabelChange`) so the owner's other tabs refresh their
  settings view. (Pushing the change into the *friend's* open dashboard is out of
  scope — see §7; the 403 gate makes it safe regardless.)

### 4.3 Route wiring (`cmd/server/main.go`)

Pass the category to each existing friend-view route; add the new endpoint:

| Route | Category |
|---|---|
| `GET /overview` (`entriesHandler.Overview`) | `ShareNutrition` |
| `GET /entries/day` (`entriesHandler.DayEntries`) | `ShareNutrition` |
| `GET /weight/day` (`weightHandler.WeightDay`) | `ShareWeight` |
| `GET /api/todos/day` (`todosHandler.DayTodos`) | `ShareTodos` |
| `GET /api/notes/day` (`notesHandler.Get`) | `ShareNotes` |
| `POST /links/{id}/shares` (`linksHandler.SetShares`) | *(login + CSRF; near the other link routes ~L266)* |

### 4.4 Dashboard payload (`internal/handler/entries.go` + `internal/service/links.go`)

`GET /api/dashboard` is self-only (no `RequireLinkAuth`) and **builds the friend
cards**, so per-category gating for the cards happens here.

**`GetAcceptedLinkUsers` is shared** by the dashboard (`entries.go`) **and** the
settings payload (`api.go`), which need **opposite** directions. Extend it to return
**both** maps per link (`$1` = me):
- `SharesToMe` = the friend's shares **toward me** =
  `CASE WHEN al.requester_id = $1 THEN target_shares ELSE requester_shares END`
  → used by the **dashboard** to gate what I see of them.
- `SharesWithThem` = **my** shares **toward the friend** =
  `CASE WHEN al.requester_id = $1 THEN requester_shares ELSE target_shares END`
  → serialized into the **settings** `AcceptedLink` payload (§5.3) to seed the checkboxes.

(When I am the requester, the friend is the target and vice-versa; the two `CASE`s
just pick opposite columns.) Add both as `map[string]bool` fields on `LinkUser`.

- In the friend-card loop (dashboard, using `SharesToMe`):
  - Compute nutrition `dailyStats` **only if** `SharesToMe[ShareNutrition]`; otherwise
    emit **empty** `dailyStats` (no dots) — the card still appears so its todos/notes/
    weight remain reachable.
  - Attach a `shares` object to every `SharedView`:
    - Self card: all four `true`.
    - Friend card: `{nutrition,weight,todos,notes}` from `SharesToMe`.
  - **Drop** a friend card entirely only if the friend shares **nothing**
    (`SharesToMe` all false) — nothing to show. (Open question resolved: hide the
    empty card rather than render a dead card.)

No change to the friend-view read endpoints' bodies — they already 403 upstream via
the middleware when not shared.

## 5. Frontend (`client/`)

### 5.1 Types (`client/src/types/index.ts`)

Add the same shape to **both** link types (call it `LinkShares`):
```ts
interface LinkShares { nutrition: boolean; weight: boolean; todos: boolean; notes: boolean }
```
- `SharedView.shares: LinkShares` — the friend's shares **toward me** (dashboard gating).
- `AcceptedLink.shares: LinkShares` — **my** shares **toward the friend** (settings checkboxes).

### 5.2 Dashboard render gating (`client/src/pages/Dashboard/Dashboard.tsx`)

When viewing a **friend** (`!isSelf` / `!canEdit`), render each section only if the
selected view shares that category; **self-view is unchanged** (all sections show):

- Resolve the active `SharedView` from `dashboard.sharedViews` by `currentUserId`.
- `EntryList` / `TodayPanel` nutrition detail → gate on `shares.nutrition`.
- `WeightRow` → gate on `shares.weight`.
- `TodoList` → gate on `shares.todos`.
- `NoteEditor` → gate on `shares.notes`.
- `ShareCard` dots already come from the (now possibly empty) `dailyStats`.

The 403 from a not-shared endpoint is treated as "not shared" (render nothing / no
error toast) as defense-in-depth, but the `shares` flags mean we normally never call
a blocked endpoint.

### 5.3 Link settings UI (`client/src/pages/Settings/LinkSettings.tsx`)

Under each **accepted** link, add a compact row of four checkboxes — **"Nutrition,
Weight, Todos, Daily notes"** — labeled as *what you share with this person*
(e.g. heading "You share with them:"). Reflects the current outgoing map; toggling
calls the new API and optimistically updates. Copy makes clear it's read-only and
one-directional.

- `client/src/api/links.ts`: add `setLinkShares(linkId, shares)` →
  `POST /links/{id}/shares`. The settings payload that carries `acceptedLinks`
  (built in `internal/handler/api.go`, ~L185, from `GetAcceptedLinkUsers`) must
  serialize each link's `SharesWithThem` as `AcceptedLink.shares` so the checkboxes
  render their current state.

## 6. Data flow (summary)

```
Owner (Settings) --toggle--> POST /links/{id}/shares --> account_links.<dir>_shares
                                                             |
Friend dashboard --GET /api/dashboard--> Dashboard reads SharesToMe
   card appears iff any-shared; nutrition dots iff nutrition shared; shares[] emitted
Friend clicks card --GET /api/{entries,weight,todos,notes}/day?user=owner-->
   RequireLinkAuth(category) checks owner's <dir>_shares[category]  --> 200 or 403
```

## 7. Testing & Verification (quality gate — end-to-end)

- **Go — middleware** (`internal/middleware/links_test.go`, new/extended): for each
  category — linked + shared → next handler runs (200); linked + **not** shared →
  403; **not** linked → 403; self-view → always allowed (no category check).
- **Go — handler** (`internal/handler/links_test.go`, extend): `SetShares` updates
  **only the caller's** direction (assert the other direction untouched), rejects a
  link the caller isn't part of (404), requires CSRF, sanitizes unknown keys.
- **Go — dashboard** (`internal/handler/entries_test.go` or `links_test.go`): a
  friend sharing only `todos` → card present, `dailyStats` empty, `shares.todos`
  true and others false; a friend sharing nothing → card absent.
- **Migration** (`internal/database/migrations_order_test.go` / existing idempotency
  test): `ensureAccountLinksSchema` still runs twice cleanly with the new columns;
  a pre-existing link row reads as all-off.
- **e2e (Playwright)** `e2e/link-sharing.spec.ts`: two linked users; owner enables
  **Todos** only → friend sees the owner's todos but **not** notes/weight/nutrition;
  owner enables **Nutrition** → friend's card shows dots and entries. (Client has no
  unit-test runner, so behavior is covered here.)
- **Build:** `go build ./...`, `go test ./...`, `cd client && npm run build` (tsc).
- **Run it:** bring up `compose.dev.yml`, create two accounts, link them, and drive
  the toggles with real data before declaring done — confirm default-off (a fresh
  link shows nothing), each toggle reveals exactly its category, and the friend
  cannot write. Verify a not-shared endpoint returns 403 (network tab).

## 8. Out of Scope

- **Live push** of a share change into the *friend's* already-open dashboard (they
  see it on next refresh; the 403 gate keeps it correct meanwhile).
- Per-individual-item sharing (specific todos / specific note dates).
- Any change to write permissions (stays read-only), to the link request/accept flow,
  or to the pending-link states.
- Android app (separate repo); the server API stays clean for it to follow later.
- Notifying the friend that sharing changed.

## 9. Files Touched (map for implementers)

**Backend**
- `internal/database/migrations.go` — extend `ensureAccountLinksSchema` with the two
  JSONB columns.
- `internal/service/links.go` — category constants + `ShareCategories`;
  `LinkUser.SharesToMe` **and** `LinkUser.SharesWithThem`; extend
  `GetAcceptedLinkUsers` SELECT/Scan to return both direction maps.
- `internal/middleware/links.go` — `RequireLinkAuth(pool, category)`; replace the
  EXISTS check with the category-aware query.
- `internal/handler/settings.go` — `LinksHandler.SetShares`.
- `internal/handler/api.go` — serialize `SharesWithThem` into the `acceptedLinks`
  settings payload (~L185).
- `internal/handler/entries.go` — `Dashboard`: gate nutrition dots (via `SharesToMe`),
  emit per-view `shares`, drop fully-unshared friend cards.
- `internal/sse/broker.go` — `BroadcastLinkSharesChange` (+ event type).
- `cmd/server/main.go` — pass category to the 5 friend-view routes; register
  `POST /links/{id}/shares`.

**Frontend**
- `client/src/types/index.ts` — `SharedView.shares`.
- `client/src/pages/Dashboard/Dashboard.tsx` — per-category render gating for friends.
- `client/src/pages/Settings/LinkSettings.tsx` — four share checkboxes per link.
- `client/src/api/links.ts` — `setLinkShares`; consume `shares` in the links payload.

**Tests/docs**
- `internal/middleware/links_test.go`, `internal/handler/links_test.go`,
  `e2e/link-sharing.spec.ts`.
- `README.md` — refine the "Account linking to share data with friends" line to note
  granular, opt-in, read-only per-category sharing.
