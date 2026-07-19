# Granular Link Sharing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each user per-friend, per-category (nutrition/weight/todos/notes), opt-in, read-only control over what a linked friend can see.

**Architecture:** Two JSONB share-maps (`requester_shares`, `target_shares`) on `account_links` — directional, exactly like the existing `requester_label`/`target_label` pair. A category-aware `RequireLinkAuth(pool, category)` gates every friend-view read; the dashboard handler gates nutrition dots and emits a per-view `shares` object; a `POST /links/{id}/shares` endpoint (mirroring `LinkLabel`) sets the caller's outgoing map; the settings UI shows four checkboxes per link. Everything defaults **off** — absent JSONB key ⇒ not shared ⇒ existing links go dark with zero data migration.

**Tech Stack:** Go 1.x (chi router, pgx/v5, standard `net/http`), React + TypeScript (Vite, TanStack Query, Zustand), Playwright e2e, Postgres.

## Global Constraints

- **Spec:** `docs/superpowers/specs/2026-07-19-granular-link-sharing-design.md` (already on `staging` and in this worktree) is the contract.
- **Branch/merge:** Work on `granular-link-sharing` (this worktree). Merge to `staging` when done; **never commit to `main`** (schautrack CLAUDE.md).
- **Conventional Commits** (CI computes semver): use `feat(links): …`, `test(links): …`, `docs(links): …`.
- **Category keys are exactly** `"nutrition"`, `"weight"`, `"todos"`, `"notes"` — never abbreviated or reordered in a way that changes the stored keys.
- **Default OFF:** absent JSONB key ⇒ false ⇒ not shared. Existing rows (`'{}'`) ⇒ all off. No backfill `UPDATE`.
- **Read-only is preserved:** never add a write path for a friend. All mutations stay on `GetCurrentUser`.
- **Direction rule (memorize):** a user's *outgoing* shares live in `requester_shares` when they are `requester_id`, else `target_shares`. `$1`=me/viewer, `$2`=sharer/target throughout.
- **Test reality:** Go DB-integration tests are **env-gated behind `TEST_DATABASE_URL` and skipped in CI** (see `internal/service/weightgoal_test.go`). CI's real coverage of DB behavior is **Playwright e2e**. So: pure logic → Go unit tests; DB behavior → e2e (Task 9). Every backend task must still leave `go build ./...` and `go vet ./...` green before commit.
- **Frontend has no unit-test runner:** frontend tasks verify with `cd client && npm run build` (tsc typecheck) and are behaviorally covered by e2e.
- **No new dependencies.** Mirror existing patterns (`LinkLabel`, `BroadcastLinkLabelChange`, JSONB idioms like `macros_enabled`).

---

### Task 1: Migration — share-map columns on `account_links`

**Files:**
- Modify: `internal/database/migrations.go` (inside `ensureAccountLinksSchema`, the `ALTER TABLE account_links ADD COLUMN IF NOT EXISTS …` block, ~L81-84)
- Test: `internal/database/migrations_test.go` (env-gated; add a columns-exist assertion)

**Interfaces:**
- Produces: columns `account_links.requester_shares JSONB NOT NULL DEFAULT '{}'` and `account_links.target_shares JSONB NOT NULL DEFAULT '{}'`.

- [ ] **Step 1: Add the two columns to the existing ALTER**

In `internal/database/migrations.go`, extend the `ADD COLUMN IF NOT EXISTS` list in `ensureAccountLinksSchema` so it reads:

```go
			ALTER TABLE account_links
				ADD COLUMN IF NOT EXISTS label TEXT,
				ADD COLUMN IF NOT EXISTS requester_label TEXT,
				ADD COLUMN IF NOT EXISTS target_label TEXT,
				ADD COLUMN IF NOT EXISTS requester_shares JSONB NOT NULL DEFAULT '{}'::jsonb,
				ADD COLUMN IF NOT EXISTS target_shares    JSONB NOT NULL DEFAULT '{}'::jsonb;
```

Leave the rest of the function (indexes, the `UPDATE … label` backfill) unchanged.

- [ ] **Step 2: Add an env-gated idempotency + columns assertion**

Append to `internal/database/migrations_test.go` (mirrors the existing env-gated test's skip pattern):

```go
func TestAccountLinksShareColumns(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	// Running twice must be clean (idempotent).
	if err := ensureAccountLinksSchema(ctx, pool); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := ensureAccountLinksSchema(ctx, pool); err != nil {
		t.Fatalf("second run: %v", err)
	}

	for _, col := range []string{"requester_shares", "target_shares"} {
		var exists bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM information_schema.columns
			WHERE table_name='account_links' AND column_name=$1 AND data_type='jsonb')`, col).Scan(&exists)
		if err != nil || !exists {
			t.Fatalf("column %s missing (err=%v)", col, err)
		}
	}
}
```

Ensure the file's imports include `context`, `os`, and `github.com/jackc/pgx/v5/pgxpool` (copy from the existing env-gated test in the same file if not already present).

- [ ] **Step 3: Verify build + vet (CI-visible gate)**

Run: `go build ./... && go vet ./internal/database/`
Expected: no output, exit 0.

- [ ] **Step 4: (Optional, local) run the migration test against a DB**

Run: `TEST_DATABASE_URL='postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable' go test ./internal/database/ -run TestAccountLinksShareColumns -v`
Expected: PASS (or `SKIP` if no local DB — behavior is re-verified by the e2e stack in Task 9, which runs all migrations on boot).

- [ ] **Step 5: Commit**

```bash
git add internal/database/migrations.go internal/database/migrations_test.go
git commit -m "feat(links): add per-direction JSONB share-maps to account_links"
```

---

### Task 2: Service — category constants + both share directions on `LinkUser`

**Files:**
- Modify: `internal/service/links.go`
- Test: `internal/service/links_test.go` (pure unit test, no DB)

**Interfaces:**
- Produces:
  - `service.ShareNutrition`, `service.ShareWeight`, `service.ShareTodos`, `service.ShareNotes` (string consts)
  - `service.ShareCategories []string`
  - `service.SanitizeShareMap(raw map[string]bool) map[string]bool` — returns a map with exactly the four keys, each an explicit bool.
  - `LinkUser.SharesWithThem map[string]bool` (json `"shares"`) — the caller's outgoing map.
  - `LinkUser.SharesToMe map[string]bool` (json `"-"`) — the friend's map toward the caller.
  - `GetAcceptedLinkUsers` now populates both maps.

- [ ] **Step 1: Write the failing unit test**

Create/append `internal/service/links_test.go`:

```go
package service

import "testing"

func TestSanitizeShareMap(t *testing.T) {
	got := SanitizeShareMap(map[string]bool{
		"nutrition": true,
		"todos":     true,
		"bogus":     true, // unknown key must be dropped
		// weight, notes omitted -> must default false
	})
	want := map[string]bool{"nutrition": true, "weight": false, "todos": true, "notes": false}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (map=%v)", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %q = %v, want %v", k, got[k], v)
		}
	}
	if _, ok := got["bogus"]; ok {
		t.Errorf("unknown key was not dropped: %v", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/service/ -run TestSanitizeShareMap -v`
Expected: FAIL — `undefined: SanitizeShareMap`.

- [ ] **Step 3: Add constants, `SanitizeShareMap`, and a decode helper**

In `internal/service/links.go`, add near the top (after the imports):

```go
// Share categories a user can expose to a linked friend. Read-only always.
const (
	ShareNutrition = "nutrition"
	ShareWeight    = "weight"
	ShareTodos     = "todos"
	ShareNotes     = "notes"
)

// ShareCategories is the canonical, ordered set of shareable categories.
var ShareCategories = []string{ShareNutrition, ShareWeight, ShareTodos, ShareNotes}

// SanitizeShareMap returns a map with exactly the four known keys (unknown keys
// dropped, missing keys defaulted to false). Storing explicit falses keeps the
// map self-describing for the settings UI; absent-key-means-off still holds.
func SanitizeShareMap(raw map[string]bool) map[string]bool {
	out := make(map[string]bool, len(ShareCategories))
	for _, c := range ShareCategories {
		out[c] = raw[c]
	}
	return out
}

// decodeShareMap parses a JSONB share-map (nil/empty ⇒ all off) and normalizes it.
func decodeShareMap(b []byte) map[string]bool {
	m := map[string]bool{}
	if len(b) > 0 {
		_ = json.Unmarshal(b, &m)
	}
	return SanitizeShareMap(m)
}
```

`json` is already imported in this file.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/service/ -run TestSanitizeShareMap -v`
Expected: PASS.

- [ ] **Step 5: Add both share fields to `LinkUser`**

In the `LinkUser` struct, add two fields at the end:

```go
	// SharesWithThem is what the caller shares toward the linked friend
	// (serialized into the settings acceptedLinks payload as "shares").
	SharesWithThem map[string]bool `json:"shares"`
	// SharesToMe is what the friend shares toward the caller (dashboard only).
	SharesToMe map[string]bool `json:"-"`
```

- [ ] **Step 6: Extend `GetAcceptedLinkUsers` to select and scan both maps**

In `GetAcceptedLinkUsers`, add two columns to the SELECT (after `u.macros_enabled AS other_macros_enabled`, keeping the trailing comma correct):

```sql
			u.macros_enabled AS other_macros_enabled,
			CASE WHEN al.requester_id = $1 THEN al.requester_shares ELSE al.target_shares END AS shares_with_them,
			CASE WHEN al.requester_id = $1 THEN al.target_shares    ELSE al.requester_shares END AS shares_to_me
```

Add two `[]byte` locals and extend the `Scan` call, then decode:

```go
		var lu LinkUser
		var timezone *string
		var macroGoals, macrosEnabled []byte
		var sharesWithThem, sharesToMe []byte
		if err := rows.Scan(&lu.LinkID, &lu.Label, &lu.UserID, &lu.Email,
			&lu.DailyGoal, &macroGoals, &timezone, &lu.GoalThreshold, &macrosEnabled,
			&sharesWithThem, &sharesToMe); err != nil {
			continue
		}
		lu.SharesWithThem = decodeShareMap(sharesWithThem)
		lu.SharesToMe = decodeShareMap(sharesToMe)
```

(Leave the existing timezone/macroGoals/macrosEnabled normalization below unchanged.)

- [ ] **Step 7: Verify build, vet, and the whole service package**

Run: `go build ./... && go vet ./internal/service/ && go test ./internal/service/ -run TestSanitizeShareMap`
Expected: PASS, exit 0.

- [ ] **Step 8: Commit**

```bash
git add internal/service/links.go internal/service/links_test.go
git commit -m "feat(links): expose both share directions from GetAcceptedLinkUsers"
```

---

### Task 3: Middleware — category-aware `RequireLinkAuth` + update call sites

**Files:**
- Modify: `internal/middleware/links.go`
- Modify: `cmd/server/main.go` (5 `RequireLinkAuth` call sites; add `service` import if missing)

**Interfaces:**
- Consumes: `service.ShareNutrition/Weight/Todos/Notes` (Task 2).
- Produces: `RequireLinkAuth(pool *pgxpool.Pool, category string) func(http.Handler) http.Handler`. Friend-view is allowed only if the target user's outgoing map has `category=true`; otherwise 403. Self-view unchanged.

- [ ] **Step 1: Change the signature and the authorization query**

In `internal/middleware/links.go`:

Update the function signature:

```go
func RequireLinkAuth(pool *pgxpool.Pool, category string) func(http.Handler) http.Handler {
```

Replace the existing "Check if linked" `EXISTS` block (the `var exists bool` query and its `if !exists` handling) with a category-aware check:

```go
				// Authorized only if the target user shares this category with us.
				var shared bool
				err = pool.QueryRow(r.Context(), `
					SELECT COALESCE(
						(CASE WHEN requester_id = $2 THEN requester_shares ELSE target_shares END ->> $3)::boolean,
						false)
					FROM account_links
					WHERE status = 'accepted'
						AND ((requester_id = $1 AND target_id = $2) OR (requester_id = $2 AND target_id = $1))`,
					currentUser.ID, targetUserID, category).Scan(&shared)
				if err != nil {
					if errors.Is(err, pgx.ErrNoRows) {
						// Not linked at all ⇒ forbidden (not a server error).
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusForbidden)
						json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "Not authorized"})
						return
					}
					log.Printf("Link auth check failed: %v", err)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "Authorization check failed"})
					return
				}
				if !shared {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "Not authorized"})
					return
				}
```

Add `"errors"` and `"github.com/jackc/pgx/v5"` to the file's imports (it already imports `pgxpool`, `json`, `log`, `net/http`, `strconv`, and `schautrack/internal/model`).

- [ ] **Step 2: Update the 5 call sites in `cmd/server/main.go`**

Change each `middleware.RequireLinkAuth(pool)` to pass its category:

```go
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool, service.ShareNutrition)).Get("/overview", entriesHandler.Overview)
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool, service.ShareNutrition)).Get("/entries/day", entriesHandler.DayEntries)
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool, service.ShareWeight)).Get("/weight/day", weightHandler.WeightDay)
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool, service.ShareTodos)).Get("/api/todos/day", todosHandler.DayTodos)
	r.With(middleware.RequireLogin, middleware.RequireLinkAuth(pool, service.ShareNotes)).Get("/api/notes/day", notesHandler.Get)
```

If `cmd/server/main.go` does not already import `schautrack/internal/service`, add it to the import block.

- [ ] **Step 3: Verify build + vet (behavior is covered by Task 9 e2e)**

Run: `go build ./... && go vet ./internal/middleware/ ./cmd/server/`
Expected: no output, exit 0. (A signature mismatch at any call site fails here — that's the gate.)

- [ ] **Step 4: Commit**

```bash
git add internal/middleware/links.go cmd/server/main.go
git commit -m "feat(links): gate friend-view reads on per-category share flags"
```

---

### Task 4: Endpoint — `POST /links/{id}/shares` + SSE broadcast

**Files:**
- Modify: `internal/handler/settings.go` (add `LinksHandler.SetShares`, mirroring `LinkLabel` at ~L821)
- Modify: `internal/sse/broker.go` (add `BroadcastLinkSharesChange`)
- Modify: `cmd/server/main.go` (register the route near the other `/links` / `/settings/link` routes ~L266)

**Interfaces:**
- Consumes: `service.SanitizeShareMap` (Task 2), `sse.Broker`.
- Produces: `POST /links/{id}/shares` accepting `{"nutrition":bool,"weight":bool,"todos":bool,"notes":bool}`, updating only the caller's direction; returns `{"ok":true,"shares":{…}}`. `Broker.BroadcastLinkSharesChange(linkID, userID int, shares map[string]bool)`.

- [ ] **Step 1: Add the SSE broadcast method**

In `internal/sse/broker.go`, after `BroadcastLinkLabelChange` (~L135):

```go
func (b *Broker) BroadcastLinkSharesChange(linkID, userID int, shares map[string]bool) {
	b.SendEvent(userID, "link-shares-change", map[string]any{
		"linkId": linkID, "shares": shares,
	})
}
```

- [ ] **Step 2: Add the `SetShares` handler**

In `internal/handler/settings.go`, after `LinkLabel`:

```go
// SetShares handles POST /links/{id}/shares — sets what the caller shares with
// the linked friend (per-category, read-only). Only the caller's own direction
// is updated; the friend's direction is untouched.
func (h *LinksHandler) SetShares(w http.ResponseWriter, r *http.Request) {
	linkID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid link")
		return
	}

	var body map[string]bool
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	shares := service.SanitizeShareMap(body)
	sharesJSON, _ := json.Marshal(shares)

	user := middleware.GetCurrentUser(r)

	var saved []byte
	err = h.Pool.QueryRow(r.Context(), `
		UPDATE account_links
		SET requester_shares = CASE WHEN requester_id = $3 THEN $1::jsonb ELSE requester_shares END,
			target_shares    = CASE WHEN target_id    = $3 THEN $1::jsonb ELSE target_shares    END,
			updated_at = NOW()
		WHERE id = $2 AND status = 'accepted' AND ($3 = requester_id OR $3 = target_id)
		RETURNING CASE WHEN requester_id = $3 THEN requester_shares ELSE target_shares END`,
		sharesJSON, linkID, user.ID).Scan(&saved)
	if err != nil {
		ErrorJSON(w, http.StatusNotFound, "Link not found")
		return
	}

	var savedMap map[string]bool
	json.Unmarshal(saved, &savedMap)
	savedMap = service.SanitizeShareMap(savedMap)
	h.Broker.BroadcastLinkSharesChange(linkID, user.ID, savedMap)
	JSON(w, http.StatusOK, map[string]any{"ok": true, "shares": savedMap})
}
```

Confirm `internal/handler/settings.go` imports `encoding/json`, `strconv`, `github.com/go-chi/chi/v5` (aliased `chi`), `schautrack/internal/middleware`, and `schautrack/internal/service` — all are already used by `LinkLabel`/other handlers in the file; add any that are missing.

- [ ] **Step 3: Register the route**

In `cmd/server/main.go`, next to the other link routes (after `/links/{id}/label`, ~L266):

```go
	r.With(middleware.RequireLogin, session.CsrfProtection).Post("/links/{id}/shares", linksHandler.SetShares)
```

- [ ] **Step 4: Verify build + vet**

Run: `go build ./... && go vet ./internal/handler/ ./internal/sse/`
Expected: no output, exit 0. (`SetShares` reuses the already-unit-tested `service.SanitizeShareMap`; its end-to-end behavior — only-caller's-direction updated, 404 for foreign links, CSRF — is exercised by the Task 9 e2e, per the Global Constraints' DB-behavior-via-e2e rule. No redundant Go re-test of the sanitizer here.)

- [ ] **Step 5: Commit**

```bash
git add internal/handler/settings.go internal/sse/broker.go cmd/server/main.go
git commit -m "feat(links): add POST /links/{id}/shares to set outgoing share flags"
```

---

### Task 5: Dashboard — emit per-view `shares` and gate nutrition dots

**Files:**
- Modify: `internal/handler/entries.go` (`Dashboard`, the self card ~L231-237 and the friend-card goroutine ~L244-287)

**Interfaces:**
- Consumes: `LinkUser.SharesToMe` (Task 2), `service.ShareNutrition/Weight/Todos/Notes`.
- Produces: each `SharedView` in the `sharedViews` payload carries `"shares": {nutrition,weight,todos,notes}`. Friend cards with nutrition unshared have empty `dailyStats`; friends sharing nothing are omitted. (No `api.go` change needed — the settings `acceptedLinks` payload already serializes `LinkUser.SharesWithThem` as `"shares"` via its json tag.)

- [ ] **Step 1: Add `shares` to the self ("You") card**

In `Dashboard`, extend the self card map (~L232-236) with an all-true share map:

```go
	sharedViews := []any{
		map[string]any{
			"userId": user.ID, "email": user.Email, "label": "You", "isSelf": true,
			"dailyGoal": dailyGoal, "goalThreshold": mu.GoalThreshold,
			"dailyStats": dailyStats, "todayStr": todayStrTz,
			"shares": map[string]bool{
				service.ShareNutrition: true, service.ShareWeight: true,
				service.ShareTodos: true, service.ShareNotes: true,
			},
		},
	}
```

- [ ] **Step 2: Gate nutrition work and emit `shares` in the friend-card goroutine**

Replace the body of the friend goroutine from the `linkGoal := …` line down through the `linkResults[i] = …` assignment (~L261-286) with:

```go
				linkGoal := service.GetCalorieGoal(lmu)
				shares := link.SharesToMe

				// Omit the card entirely if the friend shares nothing with us.
				if !shares[service.ShareNutrition] && !shares[service.ShareWeight] &&
					!shares[service.ShareTodos] && !shares[service.ShareNotes] {
					return
				}

				label := link.Email
				if link.Label != nil && strings.TrimSpace(*link.Label) != "" {
					label = *link.Label
				}

				// Nutrition dots only when nutrition is shared; otherwise empty.
				stats := []dailyStat{}
				if shares[service.ShareNutrition] {
					linkTotals, linkMacroAll, err := getTotalsAndMacrosByDate(r.Context(), h.Pool, link.UserID, linkOldest, linkNewest)
					if err != nil {
						slog.Error("dashboard: failed to load linked user's calorie totals", "error", err, "linkUserId", link.UserID)
						return
					}
					linkEnabledMacros := service.GetEnabledMacros(lmu)
					linkMacroGoals := service.GetMacroGoals(lmu)
					linkMacroModes := service.GetMacroModes(lmu)
					var linkMacroTotals map[string]map[string]int
					if len(linkEnabledMacros) > 0 {
						linkMacroTotals = linkMacroAll
					}
					stats = buildDailyStats(linkDayOptions, linkTotals, linkGoal, linkEnabledMacros, linkMacroGoals, linkMacroModes, linkMacroTotals, lmu.GoalThreshold)
				}

				linkResults[i] = linkResult{index: i, view: map[string]any{
					"linkId": link.LinkID, "userId": link.UserID, "email": link.Email,
					"label": label, "isSelf": false,
					"dailyGoal": linkGoal, "goalThreshold": lmu.GoalThreshold,
					"dailyStats": stats, "todayStr": linkTodayStr,
					"shares": shares,
				}}
```

Note: `linkOldest`/`linkNewest`/`linkDayOptions`/`linkTodayStr`/`lmu` are already computed above this block; keep those lines. `getTotalsAndMacrosByDate` now runs only when nutrition is shared (a small efficiency win).

- [ ] **Step 3: Verify build + vet**

Run: `go build ./... && go vet ./internal/handler/`
Expected: no output, exit 0.

- [ ] **Step 4: Commit**

```bash
git add internal/handler/entries.go
git commit -m "feat(links): dashboard emits per-view shares and gates nutrition dots"
```

---

### Task 6: Frontend — types + API client

**Files:**
- Modify: `client/src/types/index.ts` (add `LinkShares`; add `shares` to `SharedView` and `AcceptedLink`)
- Modify: `client/src/api/links.ts` (add `setLinkShares`)

**Interfaces:**
- Produces: `LinkShares` type; `SharedView.shares: LinkShares`; `AcceptedLink.shares: LinkShares`; `setLinkShares(linkId: number, shares: LinkShares): Promise<{ok:boolean; shares:LinkShares}>`.

- [ ] **Step 1: Add the `LinkShares` type and extend the two interfaces**

In `client/src/types/index.ts`, add the type (near `SharedView`):

```ts
export interface LinkShares {
  nutrition: boolean;
  weight: boolean;
  todos: boolean;
  notes: boolean;
}
```

Add `shares: LinkShares;` to the `SharedView` interface (~L53) and to the `AcceptedLink` interface (~L148).

- [ ] **Step 2: Add the API function**

In `client/src/api/links.ts`, add:

```ts
import type { LinkShares } from '@/types';

export function setLinkShares(linkId: number, shares: LinkShares) {
  return api<{ ok: boolean; shares: LinkShares }>(`/links/${linkId}/shares`, {
    method: 'POST',
    body: JSON.stringify(shares),
  });
}
```

(If the file has no existing `import type` line, add the import at the top alongside `import { api } from './client';`.)

- [ ] **Step 3: Typecheck**

Run: `cd client && npm run build`
Expected: build succeeds (tsc passes). It may report unused-symbol errors if `LinkShares` isn't consumed yet — if so, this task's build is still valid because the type is exported and used by Task 7/8; if the project's tsc flags unused *local* imports only, this export is fine. If `npm run build` fails solely due to the new `shares` field being required on existing `SharedView`/`AcceptedLink` literals in tests/mocks, note the locations for Task 7/8 and proceed.

- [ ] **Step 4: Commit**

```bash
git add client/src/types/index.ts client/src/api/links.ts
git commit -m "feat(links): client types and API for per-link share flags"
```

---

### Task 7: Frontend — share checkboxes in Link settings

**Files:**
- Modify: `client/src/pages/Settings/LinkSettings.tsx` (the `LinkRow` subcomponent ~L103-140)

**Interfaces:**
- Consumes: `setLinkShares` (Task 6), `AcceptedLink.shares` (Task 6).
- Produces: four checkboxes per accepted link controlling the caller's outgoing shares.

- [ ] **Step 1: Import the API and type**

At the top of `client/src/pages/Settings/LinkSettings.tsx`, extend the imports:

```ts
import type { LinkRequest, AcceptedLink, LinkShares } from '@/types';
import { requestLink, respondToLink, removeLink, updateLinkLabel, setLinkShares } from '@/api/links';
```

- [ ] **Step 2: Add the checkbox row to `LinkRow`**

Inside the `LinkRow` component, add share state and a handler, and render the checkboxes under the existing label/remove row. Replace the `LinkRow` return's outer wrapper so the label row and the new share row stack vertically:

```tsx
function LinkRow({ link, onRemove, onUpdate }: { link: AcceptedLink; onRemove: () => void; onUpdate: () => void }) {
  const [editing, setEditing] = useState(false);
  const [label, setLabel] = useState(link.label || '');
  const [shares, setShares] = useState<LinkShares>(link.shares);
  const addToast = useToastStore((s) => s.addToast);

  const saveLabel = async () => {
    try {
      await updateLinkLabel(link.linkId, label);
      onUpdate();
    } catch (err) {
      addToast('error', err instanceof Error ? err.message : 'Failed to update label');
    }
    setEditing(false);
  };

  const toggleShare = async (cat: keyof LinkShares) => {
    const next = { ...shares, [cat]: !shares[cat] };
    setShares(next); // optimistic
    try {
      const res = await setLinkShares(link.linkId, next);
      setShares(res.shares);
    } catch (err) {
      setShares(shares); // revert
      addToast('error', err instanceof Error ? err.message : 'Failed to update sharing');
    }
  };

  const CATS: { key: keyof LinkShares; label: string }[] = [
    { key: 'nutrition', label: 'Nutrition' },
    { key: 'weight', label: 'Weight' },
    { key: 'todos', label: 'Todos' },
    { key: 'notes', label: 'Daily notes' },
  ];

  return (
    <div className="mb-3 border-b border-border pb-3 last:border-0">
      <div className="flex items-center gap-2 mb-2 text-sm">
        {editing ? (
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            onBlur={saveLabel}
            onKeyDown={(e) => e.key === 'Enter' && saveLabel()}
            autoFocus
            className="flex-1 rounded border border-ring bg-muted/50 px-2 py-0.5 text-sm text-foreground outline-none"
          />
        ) : (
          <button type="button" onClick={() => setEditing(true)} className="flex-1 bg-transparent border-none text-foreground cursor-pointer text-left text-sm">
            {link.label || link.email}
          </button>
        )}
        <Button size="sm" variant="destructive" onClick={onRemove}>Remove</Button>
      </div>
      <div className="text-xs text-muted-foreground mb-1">You share with them (read-only):</div>
      <div className="flex flex-wrap gap-x-4 gap-y-1">
        {CATS.map(({ key, label: catLabel }) => (
          <label key={key} className="flex items-center gap-1.5 text-sm cursor-pointer">
            <input type="checkbox" checked={shares[key]} onChange={() => toggleShare(key)} />
            {catLabel}
          </label>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Typecheck**

Run: `cd client && npm run build`
Expected: build succeeds. If tsc complains that some `AcceptedLink` literal elsewhere lacks `shares`, add `shares` to that literal (the server always sends it now).

- [ ] **Step 4: Commit**

```bash
git add client/src/pages/Settings/LinkSettings.tsx
git commit -m "feat(links): per-link share checkboxes in settings"
```

---

### Task 8: Frontend — gate the friend view by shared categories

**Files:**
- Modify: `client/src/pages/Dashboard/Dashboard.tsx` (~L104-190)

**Interfaces:**
- Consumes: `SharedView.shares` (Task 6).
- Produces: when viewing a friend, only shared sections render; self-view is unchanged.

- [ ] **Step 1: Resolve the active view's shares and a gate helper**

In `Dashboard.tsx`, after `const effectiveUserId = currentUserId || dashboard?.user.id;` (~L43), add:

```tsx
  const activeView = dashboard?.sharedViews.find((v) => v.userId === effectiveUserId);
  // Self-view always shows everything (canEdit); a friend view shows only shared categories.
  const showCat = (cat: 'nutrition' | 'weight' | 'todos' | 'notes') =>
    canEdit || !!activeView?.shares?.[cat];
```

- [ ] **Step 2: Gate each section in the JSX**

Wrap the sections so friend-view respects shares. Apply these edits in the `return`:

- Wrap `TodayPanel` (~L106-118) and the Entries block (~L166-179) each in `{showCat('nutrition') && ( … )}`.
- Wrap the `TodoList` block (~L149-156) so its condition becomes `{effectiveUserId && selectedDate && showCat('todos') && ( <TodoList … /> )}`.
- Wrap the `NoteEditor` block (~L158-164) so its condition becomes `{effectiveUserId && selectedDate && showCat('notes') && ( <NoteEditor … /> )}`.
- Wrap `WeightRow` (~L181-187) in `{showCat('weight') && ( <WeightRow … /> )}`.

The `{canEdit && ( … )}` blocks (SavedFoodsRow/EntryForm ~L120-141 and PlanCard ~L189) already only render for self; leave them as-is.

- [ ] **Step 3: Typecheck**

Run: `cd client && npm run build`
Expected: build succeeds.

- [ ] **Step 4: Commit**

```bash
git add client/src/pages/Dashboard/Dashboard.tsx
git commit -m "feat(links): hide non-shared sections when viewing a friend"
```

---

### Task 9: e2e — fix default-off breakage, add coverage, update README

**Files:**
- Modify: `e2e/linked-user-data.spec.ts`, `e2e/linked-sse.spec.ts`, `e2e/linked-timezone.spec.ts` (opt-in sharing so existing assertions still pass)
- Create: `e2e/link-sharing.spec.ts`
- Modify: `README.md` (feature bullet)

**Interfaces:**
- Consumes: `psql`, `createIsolatedUser` from `e2e/fixtures/helpers`; the running app (migrations applied on boot).

- [ ] **Step 1: Opt-in sharing in the three data-viewing linked specs**

In each of `e2e/linked-user-data.spec.ts`, `e2e/linked-sse.spec.ts`, `e2e/linked-timezone.spec.ts`, immediately **after** the `INSERT INTO account_links (…) VALUES (…, 'accepted')` in `beforeAll`, add a full-share UPDATE (sets both directions, so it works regardless of who views whom). Use the two user ids already in scope in that spec — for `linked-user-data.spec.ts` they are `viewer.id`/`owner.id`:

```js
    psql(`UPDATE account_links
      SET requester_shares = '{"nutrition":true,"weight":true,"todos":true,"notes":true}'::jsonb,
          target_shares    = '{"nutrition":true,"weight":true,"todos":true,"notes":true}'::jsonb
      WHERE (requester_id = ${viewer.id} AND target_id = ${owner.id})
         OR (requester_id = ${owner.id} AND target_id = ${viewer.id})`);
```

For `linked-sse.spec.ts` use `userA.id`/`userB.id`; for `linked-timezone.spec.ts` use `viewer.id`/`creator.id` (match each file's variable names). `account-linking.spec.ts` only tests the request/accept/slot flow (its inserts use throwaway `dummyId`s and it does not switch to view another user's data), so it needs **no** change — confirm by grepping the file for `switchToOwner`/data assertions; if none, leave it.

- [ ] **Step 2: Write the new e2e spec (default-off + per-category reveal + UI toggle persistence)**

Create `e2e/link-sharing.spec.ts`:

```ts
import { test, expect } from '@playwright/test';
import { psql, createIsolatedUser } from './fixtures/helpers';

const baseURL = process.env.E2E_BASE_URL || 'http://localhost:3001';
const TODAY = new Date().toLocaleDateString('en-CA', { timeZone: 'UTC' });

let viewer: { email: string; password: string; id: string };
let owner: { email: string; password: string; id: string };

const TODO_NAME = 'E2E share-toggle todo';
const NOTE = 'E2E share-toggle note';

test.describe('Granular link sharing', () => {
  test.describe.configure({ mode: 'serial' });

  test.beforeAll(() => {
    viewer = createIsolatedUser('share-toggle-viewer');
    owner = createIsolatedUser('share-toggle-owner');
    psql(`UPDATE users SET todos_enabled = true, notes_enabled = true WHERE id = ${owner.id}`);
    // Link viewer -> owner (owner is target_id, so owner's outgoing map is target_shares).
    psql(`INSERT INTO account_links (requester_id, target_id, status)
          VALUES (${viewer.id}, ${owner.id}, 'accepted') ON CONFLICT DO NOTHING`);
    psql(`INSERT INTO daily_notes (user_id, note_date, content) VALUES (${owner.id}, '${TODAY}', '${NOTE}')
          ON CONFLICT (user_id, note_date) DO UPDATE SET content = '${NOTE}'`);
    psql(`INSERT INTO todos (user_id, name, schedule) VALUES (${owner.id}, '${TODO_NAME}', '{"type":"daily"}')
          ON CONFLICT DO NOTHING`);
  });

  test.afterAll(() => {
    if (!viewer?.id || !owner?.id) return;
    psql(`DELETE FROM account_links WHERE (requester_id = ${viewer.id} AND target_id = ${owner.id})
          OR (requester_id = ${owner.id} AND target_id = ${viewer.id})`);
  });

  function setOwnerShares(shares: Record<string, boolean>) {
    // Owner is target_id -> set target_shares.
    psql(`UPDATE account_links SET target_shares = '${JSON.stringify(shares)}'::jsonb
          WHERE requester_id = ${viewer.id} AND target_id = ${owner.id}`);
  }

  async function loginViewer(page: import('@playwright/test').Page) {
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(viewer.email);
    await page.getByLabel('Password').fill(viewer.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
  }

  // Returns the owner's ShareCard label locator (absent when nothing is shared).
  function ownerCard(page: import('@playwright/test').Page) {
    return page.locator('.text-sm.font-medium')
      .filter({ hasText: new RegExp(owner.email.split('@')[0], 'i') }).first();
  }

  test('default off: owner card is absent (nothing shared)', async ({ browser }) => {
    setOwnerShares({ nutrition: false, weight: false, todos: false, notes: false });
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginViewer(page);
    await page.getByText('Timeline').scrollIntoViewIfNeeded({ timeout: 5000 });
    await expect(ownerCard(page)).toHaveCount(0, { timeout: 5000 });
    await ctx.close();
  });

  test('todos only: viewer sees the todo but not the note', async ({ browser }) => {
    setOwnerShares({ nutrition: false, weight: false, todos: true, notes: false });
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    await loginViewer(page);
    await page.getByText('Timeline').scrollIntoViewIfNeeded({ timeout: 5000 });
    const card = ownerCard(page);
    await expect(card).toBeVisible({ timeout: 8000 });
    // Switch to the owner: click the card (its today dot, or the card itself).
    const cardRoot = card.locator('../..');
    const dot = cardRoot.locator(`button[title="${TODAY}"]`);
    if (await dot.count()) { await dot.click(); } else { await card.click(); }
    await page.waitForTimeout(500);
    await expect(page.getByText(TODO_NAME).first()).toBeVisible({ timeout: 8000 });
    await expect(page.getByText(NOTE)).toHaveCount(0, { timeout: 3000 });
    await ctx.close();
  });

  test('notes toggle persists via the settings UI', async ({ browser }) => {
    setOwnerShares({ nutrition: false, weight: false, todos: false, notes: false });
    const ctx = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const page = await ctx.newPage();
    // Log in as the OWNER and toggle "Daily notes" on for the viewer link.
    await page.goto(`${baseURL}/login`);
    await page.waitForLoadState('domcontentloaded');
    await page.getByLabel('Email').fill(owner.email);
    await page.getByLabel('Password').fill(owner.password);
    await page.getByRole('button', { name: 'Log In' }).click();
    await page.waitForURL(/\/dashboard/, { timeout: 15000 });
    await page.goto(`${baseURL}/settings`);
    await page.waitForLoadState('domcontentloaded');
    // The label wraps the checkbox — clicking the label text toggles it.
    const notesLabel = page.locator('label', { hasText: 'Daily notes' }).first();
    await notesLabel.scrollIntoViewIfNeeded({ timeout: 5000 });
    await notesLabel.click();
    // Assert it persisted server-side.
    await expect.poll(() =>
      psql(`SELECT target_shares->>'notes' FROM account_links WHERE requester_id = ${viewer.id} AND target_id = ${owner.id}`).trim(),
      { timeout: 5000 }
    ).toBe('true');
    await ctx.close();
  });
});
```

- [ ] **Step 3: Run the affected e2e specs against the running stack**

Bring the app up (per repo README / `compose.dev.yml` or the e2e harness in `playwright.config.ts`), then:

Run: `npx playwright test link-sharing linked-user-data linked-sse linked-timezone --reporter=line`
Expected: all pass. If a selector in the new spec is brittle (label/checkbox lookup), adjust it against the real DOM — the assertions (card absent when off; todo visible + note absent when todos-only; `target_shares->>'notes' = true` after the UI toggle) are the contract; keep them.

- [ ] **Step 4: Update the README feature bullet**

In `README.md`, change the account-linking feature line to reflect granular, opt-in, read-only sharing, e.g.:

```md
- Account linking to share data with friends — granular, opt-in, read-only per category (nutrition, weight, todos, daily notes)
```

- [ ] **Step 5: Commit**

```bash
git add e2e/linked-user-data.spec.ts e2e/linked-sse.spec.ts e2e/linked-timezone.spec.ts e2e/link-sharing.spec.ts README.md
git commit -m "test(links): e2e for granular sharing; opt-in existing linked specs"
```

---

## Final Verification (before merge to staging)

- [ ] `go build ./... && go vet ./... && go test ./...` — all green (DB-integration tests SKIP without `TEST_DATABASE_URL`; that's expected).
- [ ] `cd client && npm run build` — tsc + Vite build clean.
- [ ] Full e2e: `npx playwright test --reporter=line` — green (especially the four linked-* specs and `link-sharing`).
- [ ] **Manual end-to-end drive** (quality gate): with the stack up, create two accounts, link them. Confirm: (1) default — the friend's card is absent / no data visible; (2) tick **Todos** in settings → friend sees only todos; (3) tick **Nutrition** → dots + entries appear; (4) friend cannot edit anything (note textarea disabled, no Track/Delete); (5) a not-shared endpoint returns 403 (browser network tab, e.g. `GET /api/notes/day?user=<owner>`).
- [ ] Merge to staging: `git checkout staging && git merge --no-ff granular-link-sharing` (or fast-forward if staging hasn't moved), then push per your instruction.
