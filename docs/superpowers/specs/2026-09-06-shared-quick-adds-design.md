# Sharing quick-add items with a linked user

Design for [#537](https://github.com/schaurian/schautrack/issues/537).

## The ask

A self-hoster wants their partner to be able to use their quick-add items. The
reporter asked for every item to become available to everyone on the server
automatically; the maintainer declined global sharing and described the shape he
wanted instead: *"if you share with another person you can share and they can
accept. So kinda like keeping it in sync."*

Both halves matter. Per-person rather than global, and **in sync** rather than
copied.

## What already exists

Three findings shaped this design, and the third changed it.

**1. Per-person sharing is already built.** `account_links` carries
`requester_shares` and `target_shares` (jsonb), each holding a map of category →
bool for one direction of the link. The vocabulary is `service.ShareCategories`
(`nutrition`, `weight`, `todos`, `notes`), and `middleware/links.go` gates reads
on it with the direction resolved by a `CASE WHEN requester_id = $1` pair. Links
already require acceptance, and a link already caps at three per user.

**2. `saved_foods.shared` is dead schema.** A `BOOLEAN NOT NULL DEFAULT FALSE`
column plus a partial index `saved_foods_shared_idx ON saved_foods (user_id)
WHERE shared = TRUE`, both created by `migrations.go` and read by no Go code at
all. Someone started this feature and stopped.

**3. The SSE half is already done.** `Broker.BroadcastSavedFoodChange` resolves
its targets through `getTargets`, which is the source user *plus their linked
users*. Every quick-add mutation already notifies link partners; the client
simply ignores the event today because it never renders anyone else's foods.

## Decision

Add `savedfoods` to `ShareCategories`. No new tables, no offers, no
subscriptions.

Sharing is toggled per link in the settings UI that already exists. When A
shares `savedfoods` with B, A's quick-add items appear in B's quick-add row, and
B tapping one logs an entry **to B's own account**. Because nothing is copied,
A's edits are B's edits — the "in sync" half is not implemented, it is a
property of not copying.

Acceptance is the link's own acceptance, which already exists.

### Rejected: offer + accept a copy

A per-item offer that clones the row on accept. The recipient would own their
copy and could edit it, but the two diverge the moment either side changes
anything — which contradicts "keeping it in sync" directly. It also needs a new
table, new endpoints, and new UI to express something the link already expresses.

### Rejected: offer + accept a subscription

A per-item offer that creates a subscription row, so edits still propagate. This
does satisfy both halves, and it is the honest answer *if per-item granularity
is wanted*. It costs a table, an offers lifecycle, a third state in the
quick-add row, and a decision about what happens when the owner deletes a
subscribed item.

Nothing in the issue asks for per-item control — the reporter explicitly wanted
*all* items shared automatically. Building the offers machinery now would be
paying for a requirement nobody has stated. If it is ever wanted, the dead
`shared` column is where it goes, and this design does not block it.

## Implementation

### Share category

`service.ShareCategories` is the single source of truth: adding the constant
propagates to `decodeShareMap` and to `v1_links.go`'s output automatically. The
client's category list in `LinkSettings.tsx` is hardcoded, so it needs one entry
plus one i18n key across all eight locales.

### The authorization predicate — the only risky part

`Track` currently scopes with `WHERE id = $1 AND user_id = $2`, and `List` with
`WHERE user_id = $1`. Both, plus their v1 twins in `v1_foods.go`, must widen to
"owned by me, or owned by someone who shares `savedfoods` **toward** me".

This must be **one** SQL predicate used by all four call sites, not four copies.
The direction is the part that is easy to get backwards: `shares_with_them` and
`shares_to_me` come from opposite branches of the same `CASE WHEN`, and reading
the wrong one would expose foods the owner never shared — a silent
authorization inversion that every test asserting "sharing works" would still
pass.

Only `status = 'accepted'` links count, matching the existing gate.

### Reads

`savedFoodView` gains an `owner` field: `null` for the caller's own items, the
link label otherwise. Own items rank first by the existing `savedFoodRank`, then
borrowed ones by the same ranking — so a partner adding an item never reorders
the chips the user has built muscle memory for.

### Writes

`Track` writes the entry to the **caller**. Borrowed items must **not** bump the
owner's `use_count` / `last_used_at`: those drive `savedFoodRank`, so counting a
partner's usage would silently reorder the owner's own chips to reflect someone
else's habits.

`Create`, `Update` and `Delete` stay strictly owner-scoped. Borrowed items are
read-only, consistent with the existing rule that shared data is never editable.
The Manage dialog lists only the caller's own items.

### Revocation

Untick the category, or drop the link, and the chip is gone on the next fetch;
a racing `track` gets a 403 from the same predicate. No cleanup job, no orphan
state — a consequence of not copying.

### v1 API

`ListSavedFoodsV1` shares the query, so the public API surface changes with it.
Per invariant #2 the route table and the OpenAPI document must agree, and
`go run ./cmd/apidocs` must be re-run or `go test ./...` fails on stale
artifacts.

Scopes are unchanged: reading a shared food is `foods:read`, and tracking one
already requires `foods:write` on the endpoint that exists. No new scope — the
data category has not changed, only whose rows are visible.

### SSE

Nothing. `BroadcastSavedFoodChange` already fans out to linked users; the client
begins acting on an event it currently receives and drops.

### Dead column

Drop `saved_foods.shared` and `saved_foods_shared_idx` in the same change.
Nothing reads them, and a boolean named `shared` sitting next to a real sharing
feature is a trap for the next reader. If per-item control is ever built, it
comes back deliberately.

## Testing

The weight goes on the predicate, because that is the security surface and the
rest is plumbing. Table-driven over the four cases:

| case | expected |
|---|---|
| my own item | visible, trackable |
| shared toward me | visible, trackable |
| shared the *other* way (I share, they don't) | **not** visible, 403 on track |
| not linked at all | **not** visible, 403 on track |

The third row is the one that catches a reversed `CASE WHEN`, and it is the case
a naive "sharing works" test would miss entirely.

Plus one test asserting a borrowed track leaves the owner's `use_count` and
`last_used_at` untouched, and one asserting `Update`/`Delete` on a borrowed item
is refused.

## UI

Shared chips render in the same row as the user's own with a small owner marker,
rather than as a separate group: a second group makes the row taller on mobile,
and the `+ more` overflow (fixed in #533) already absorbs the extra items.

## Out of scope

- Per-item control over which quick-adds are shared.
- Editing or deleting a borrowed item.
- Sharing with anyone who is not an accepted link.
- Global / server-wide quick-adds, which the maintainer declined in the issue.
