# Sharing quick-add items with a linked user

Design for [#537](https://github.com/schaurian/schautrack/issues/537).

## The ask

A self-hoster wants their partner to be able to use their quick-add items. The
reporter asked for every item to become available to everyone on the server
automatically; the maintainer declined global sharing and described the shape he
wanted instead: *"if you share with another person you can share and they can
accept. So kinda like keeping it in sync."*

Both halves matter: per-person rather than global, and **in sync** rather than
copied.

## What already exists

**Per-person sharing is already built.** `account_links` carries
`requester_shares` and `target_shares` (jsonb), each a category → bool map for
one direction. The vocabulary is `service.ShareCategories` (`nutrition`,
`weight`, `todos`, `notes`). Links already require acceptance.

**There are two audited gates for cross-account reads, one per surface**, and a
test pinning each:

- App: `middleware.RequireLinkAuth` (`internal/middleware/links.go:25`), pinned
  by `TestLinkAuthCoverage`, which asserts *set equality* between routes mounting
  it and handlers reading a target user — and errors if such a handler sits on a
  mutating method.
- v1: `V1Handler.resolveTarget` (`internal/handler/v1_links.go:106`), which
  requires the `links:read` scope **and** the category share, answers 403 on any
  failure, and is pinned by `TestV1SharedDataIsReadOnly`.

**`saved_foods.shared` is dead schema.** A column plus partial index created by
`migrations.go:630,660` and read by no Go code.

**SSE already fans out to linked users.** `Broker.BroadcastSavedFoodChange`
(`internal/sse/broker.go:203`) resolves targets as the source user plus their
accepted links.

## Decision

Add `savedfoods` to `ShareCategories`, and route every cross-account read through
the gate that already exists on each surface. No new tables, no offers, no
subscriptions.

Not copying is what makes "in sync" free: A's edits are what B sees, because
there is only one row.

### Rejected: offer + accept a copy

The recipient would own an editable copy, but the two diverge the moment either
side edits, contradicting the ask directly.

### Rejected: offer + accept a subscription

Satisfies both halves, at the cost of a table, an offers lifecycle, a third chip
state, and a policy for the owner deleting a subscribed item. Nothing in the
issue asks for per-item control — the reporter wanted *all* items shared. If it
is ever wanted, the dead `shared` column is where it goes; this design does not
block it.

### The cost this design does carry, stated honestly

Not copying means **the recipient's button silently changes meaning**. If A edits
"Coffee" from 5 kcal to 500, B's next tap logs 500 with no signal. If A deletes
it, B's chip disappears with no explanation. Already-logged entries are safe —
`buildTrackedEntry` snapshots emoji and name into `calorie_entries.entry_name` —
so this is about future taps, not history.

That is the mirror image of the divergence problem that rules out copying, and it
is a real cost rather than a technicality. It is accepted because the alternative
loses the property the maintainer actually asked for, but it obliges the UI to
attribute borrowed chips clearly (below).

## Implementation

### Share category

`service.ShareCategories` drives `decodeShareMap` and `v1_links.go`. It does
**not** drive everything: `internal/openapi/spec.go:599-611` hand-lists the four
categories **twice** (`shares_with_me` and `shares_to_them`, in both the property
maps and the required lists). Those need editing by hand, and adding a fifth
category is a documented — additive — v1 schema change to `GET /api/v1/links`.

Client: one entry in `LinkSettings.tsx`'s hardcoded list plus one i18n key in all
eight locales.

### v1 reads: `?user=`, not a widened default

`GET /api/v1/saved-foods` gains the `user` query parameter and resolves it
through `resolveTarget(r, service.ShareSavedFoods)`, exactly as the other linked
reads do.

**It must not be a widened default response.** The endpoint's own published
description (`internal/openapi/spec.go:1150`) currently reads:

> *"**Your own foods only, deliberately.** This endpoint does not accept `user`:
> account linking shares nutrition, weight, todos, and notes, and saved foods are
> none of those, so there is no share category that could authorize reading
> another account's."*

Silently changing what the no-parameter response contains would break every
client that syncs saved foods — they would start receiving rows they cannot
`PATCH` or `DELETE` — and would falsify two more contract statements:
`SavedFoodList`'s "Every saved food on the account" (`spec.go:527`) and the
`name` field's "Unique per account, case-insensitively" (`spec.go:419`), since a
merged list can hold two chips called "Coffee".

With `?user=`, the change is purely additive: the default keeps meaning what it
has always meant, and the description is *extended* (this category now exists)
rather than retracted.

Regenerating with `go run ./cmd/apidocs` is necessary but **not sufficient** — it
would faithfully reproduce whatever prose is left in place. The description text
is hand-written and must be rewritten deliberately.

### v1 track stays owner-only

`POST /api/v1/saved-foods/{id}/track` is gated on `ScopeEntriesWrite` and nothing
else (`v1_router.go:194`). Widening its lookup to borrowed ids would let a token
holding only `entries:write` — the scope any meal-logging script requests — read
a linked account's food name, emoji and calories back out of the 201 `Entry`
response. `saved_foods.id` is a global `SERIAL`, so ids are guessable by
increment.

Route-level `RequireScope` cannot express "also needs `foods:read` and
`links:read`, but only when the id is borrowed". So v1 `track` **does not accept
borrowed ids** and keeps returning 404 for them. A v1 client that wants to log a
partner's food reads it with `?user=` and posts a normal entry. This also keeps
`resolveTarget`'s documented invariant — *"Shared data is strictly read-only. No
write endpoint calls this"* — literally true.

### App surface: an explicit scope parameter

`GET /api/saved-foods` gains `?scope=mine|all`, defaulting to **`mine`**.

The default matters because one endpoint and one React Query key feed three
consumers:

| consumer | file | needs |
|---|---|---|
| quick-add chip row | `SavedFoodsRow.tsx:40` | `all` |
| Manage dialog | `SavedFoodsModal.tsx:47` | `mine` |
| "you have N saved foods" | `SavedFoodsSettings.tsx:13` | `mine` |

All three currently share `queryKey: ['savedFoods']`. Widening the default would
make Manage offer borrowed rows for editing (404 on save) and make the Settings
count include a partner's foods against the user's own 200-item cap. The chip row
opts in with `scope=all` and a distinct query key; the other two are untouched.

### The authorization predicate

One SQL predicate — "owned by me, or owned by someone who shares `savedfoods`
toward me, over an `accepted` link" — used by the app list and the app track, and
nowhere copy-pasted.

The direction is the trap: `shares_with_them` and `shares_to_me` come from
opposite branches of one `CASE WHEN` (`service/links.go:130-131`). Reading the
wrong branch exposes foods the owner never shared, and every test asserting *that
sharing works* would still pass.

**App track must not become an unaudited cross-account path.** It reads a row it
does not own, on a mutating route — the shape `TestLinkAuthCoverage`'s second
rule exists to forbid. It will not literally trip that test, because it never
calls `GetTargetUser`, and that is precisely the problem. Either route it through
the existing middleware, or extend `TestLinkAuthCoverage` (or add a sibling) so
this path is covered by an equivalent assertion. Doing neither is not an option.

### Not-found stays 404

The repo's anti-enumeration rule is stated on `resolveTarget`: *"Any failure is
403 — never 404, which would otherwise let a caller probe which user IDs exist."*
For a **saved-food id**, the polarity is the opposite: 403 for "exists but not
shared" versus 404 for "does not exist" turns `track` into an oracle over every
user's food ids, which are sequential. Both `Track` implementations return 404
today. Keep 404 for every unreachable id, borrowed or absent.

### Writes stay owner-scoped

`Create`, `Update`, `Delete` are unchanged. Borrowed items are read-only,
matching the existing rule that shared data is never editable.

A borrowed track must **not** bump the owner's `use_count` / `last_used_at`;
those drive `savedFoodRank`, so counting a partner's usage would reorder the
owner's own chips to reflect someone else's habits. Concretely: **widen the
`SELECT`, do not touch the `UPDATE`** — the existing
`UPDATE saved_foods SET use_count = … WHERE id = $1 AND user_id = $2` already
does the right thing if left alone.

The consequence, accepted: borrowed chips carry no per-recipient ranking signal,
so their order is permanently the owner's habits, not the recipient's.

### Volume

`MaxLinks` is **10** (`internal/handler/settings.go:544`) — not 3, which is a
stale figure in `CLAUDE.md` that this spec previously repeated. That matters,
because `ListSavedFoodsV1`'s unpaginated design is justified *entirely* on the
200-item ceiling (`v1_foods.go:57-72`), and its schema declares no `has_more` or
`next_cursor` on purpose.

Worst case becomes 10 links × 200 + 200 own = **2200 rows** in one response, and
`SavedFoodsRow.tsx` renders `all.map(renderChip)` when expanded.

The app surface's `scope=all` list is therefore capped: borrowed items are
limited per link, ranked by the owner's `savedFoodRank`. v1 is unaffected because
`?user=` returns exactly one account's foods, so its 200-row bound holds
unchanged.

### UI: borrowed chips must be reachable

`SavedFoodsRow.tsx` shows `DESKTOP_CHIPS = 8` / `MOBILE_CHIPS = 6` before the
`+ more` overflow. "Own items first, borrowed after" plus "the overflow absorbs
them" cannot both be good: any user with ≥6 saved foods — trivial against a 200
cap — would never see a borrowed chip without tapping `+ more`. That hides the
entire feature behind a tap.

So: **a small dedicated group for borrowed chips**, after the user's own and
visible above the cut, rather than mixing them into one ranked list. This
reverses the recommendation an earlier draft of this spec made. Own-chip
positions stay stable, which was the real goal, and the feature is visible.

Each borrowed chip attributes its owner in the visible label *and* the accessible
name and tooltip (`Chip` currently builds its tooltip from name + macros only).
That is what makes the silent-mutation cost above tolerable: the user can see
whose item they are about to log.

### SSE needs a category filter after all

`getTargets` (`broker.go:329`) fans out to all accepted links **without
consulting the share map**, and `useSSE.ts:101` already listens for
`saved-food-change` and revalidates. Today that is harmless waste. After this
change it is a low-grade activity oracle: a partner who is *not* shared
`savedfoods` still receives an event on every one of A's quick-add edits,
multiplied by up to 10 links.

Either filter the fan-out by category, or document the timing leak deliberately.
The earlier claim that "the SSE half needs zero changes" was wrong.

### Dropping the dead column

`shared` is declared inside `CREATE TABLE IF NOT EXISTS` (`migrations.go:630`)
and its index created at `:660`. Removing both statements is not enough — an
existing database still has the column. Add
`ALTER TABLE saved_foods DROP COLUMN IF EXISTS shared`, ordered *after* the
create block, so a re-run cannot recreate the index against a dropped column.

## Testing

The predicate is the security surface:

| case | expected |
|---|---|
| my own item | visible, trackable |
| shared toward me | visible, trackable |
| shared the *other* way (I share, they don't) | **not** visible, 404 on track |
| not linked at all | **not** visible, 404 on track |

The third row is what catches a reversed `CASE WHEN`.

Also required:

- **Scope tests**: a `foods:read`-only token and an `entries:write`-only token
  must not reach a linked account's rows; `?user=` without `links:read` is 403.
- **The tests this change breaks**, which must be updated deliberately rather
  than discovered: `TestLinkMatchesSchema` and `TestLinkListMatchesSchema`
  (`v1_contract_test.go:614,629`) and `TestDecodeShareFlagsIsTotal` (`:640`,
  asserts `len(got) != 4`), plus four-category fixtures in
  `v1_linked_reads_test.go:583` and `service/links_test.go:106`.
- **Manage and the Settings count exclude borrowed items.**
- **SSE**: no `saved-food-change` to a link that is not shared `savedfoods`.
- **A borrowed track leaves the owner's `use_count`/`last_used_at` untouched.**
- **e2e**: `e2e/account-linking.spec.ts` already builds two linked users. The
  share → see chip → track → revoke → chip gone flow is exactly what it is for,
  and the revocation behaviour is otherwise only asserted in prose.

## Already satisfied — no work needed

- **Invariant #6 (`Idempotency-Key`)**: no new POST, and `track` is already
  wrapped, keyed `(user_id, idempotency_key)` on the *caller*
  (`v1_idempotency.go:135`), so it is per-caller safe unchanged.
- **Export/import**: `entries_export.go` covers only entries and weights; saved
  foods are not exported at all.
- **Account deletion**: `saved_foods.user_id` is `ON DELETE CASCADE`, so borrowed
  chips vanish correctly with the owner.
- **Id collisions**: `saved_foods.id` is a global `SERIAL`, so a merged list has
  unique ids.

## Out of scope

- Per-item control over which quick-adds are shared.
- Editing or deleting a borrowed item.
- Borrowed ids on the v1 `track` endpoint (see above).
- Global / server-wide quick-adds, declined in the issue.
