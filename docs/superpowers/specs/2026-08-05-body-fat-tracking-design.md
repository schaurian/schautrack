# Body-Fat Tracking — Design Spec

**Date:** 2026-08-05
**Branch:** `worktree-bodyfat-tracking` (off `staging`)
**Status:** Approved to implement (user delegated all decisions: "think about how it would make sense and implement it")

## 1. Problem & Goal

Schautrack logs **weight**, but weight alone is a poor progress signal. A user
on a deficit who loses 4 kg has no way to tell whether that was fat or lean
mass — the single most important question in a weight-loss program. Every
consumer smart scale reports body fat % alongside weight, and that number is
currently thrown away.

This feature adds an **optional body-fat percentage** to the existing per-day
weight reading, and uses it where it actually changes an answer:

1. **Composition over time** — lean mass and fat mass, plotted next to weight.
2. **A better calorie budget** — with body fat known, BMR comes from
   **Katch–McArdle** (lean mass) instead of **Mifflin–St Jeor** (total mass),
   which is the more accurate estimator for anyone away from average body
   composition.
3. **A lean-mass-aware projection** — the plan curve decelerates from lean-mass
   loss rather than from total-weight loss.

## 2. Decisions (locked)

| Decision | Choice | Why |
|---|---|---|
| Storage | **New nullable `body_fat` column on `weight_entries`** — not a new table | Body fat comes off the same scale reading as weight, at the same cadence. A column inherits the one-row-per-day invariant, delete semantics, export/import, SSE and link-sharing for free. |
| Requires a weight | Yes — body fat lives on a weight row (`weight` stays `NOT NULL`) | Every derived value (lean mass, fat mass, Katch–McArdle BMR) needs both. |
| Opt-in | New `users.body_fat_enabled` flag, default `false` | Matches the existing `todos_enabled` / `notes_enabled` precedent. Most users don't own a body-composition scale; the dashboard stays clean for them. |
| Toggle location | Its **own settings card**, beside Todos and Daily Notes, with `POST /weight/toggle-body-fat` | First built into the Preferences card to avoid a new endpoint — but that card is headed *Internationalization* (language, weight unit, timezone), and "Track body fat" plainly is not. The toggle-card pattern already exists for exactly this. |
| Unit | Percent, always. Never converted for kg/lb users. | A percentage is unit-independent. Derived **lean/fat mass are weights** and *do* convert. |
| BMR formula | **Katch–McArdle when a body-fat reading exists, Mifflin–St Jeor otherwise**; the response says which was used | Automatic upgrade, no new user decision, graceful when absent. |
| Profile completeness | **Unchanged** — `metrics.complete` still requires height + birth year + sex + activity level | Katch–McArdle needs neither sex nor height nor age, so body fat *could* unlock a budget with fewer fields. Deliberately not doing that: it would fork the "complete profile" UX for marginal gain. |
| Sharing | Rides along with the existing **`weight`** share category | Same data category, already an explicit opt-in per link. No new toggle. |
| Body-fat *goal* | **Out of scope** | A target-body-fat goal is a second goal type (own pace math, own guardrails). Weight goals stay the only goal. |

**Rejected alternatives:** a separate `body_fat_entries` table (doubles the
handler/export/import/sharing plumbing for a value that is always measured with
weight); always-visible input with no flag (permanent clutter for the majority);
client-side composition math (server is the single source of truth for all plan
math — see the planner spec).

## 3. The Math (`internal/service/bodycomp.go`, pure, table-driven tests)

```
LeanBodyMass(weightKg, bodyFatPct) = weightKg × (1 − bodyFatPct/100)
FatMass(weightKg, bodyFatPct)      = weightKg × (bodyFatPct/100)
BMRKatchMcArdle(leanMassKg)        = 370 + 21.6 × leanMassKg
```

**Body-fat categories** (American Council on Exercise bands). Lower bound of
each band, by sex:

| | athletic | fitness | average | obese |
|---|---|---|---|---|
| male | 6 | 14 | 18 | 25 |
| female | 14 | 21 | 25 | 32 |
| other | 10 | 17.5 | 21.5 | 28.5 |

Below the athletic bound is `essential`. The `other` row is the male/female
midpoint, mirroring how `BMR` already averages the sex constant (`c = −78`) and
how `CalorieFloor` picks a middle value for `other`. With **no sex recorded**,
the category is omitted — the percentage, lean mass and fat mass still show.

**Projection with known body fat.** `AdaptivePlanCurve` currently recomputes
Mifflin BMR at each simulated week, so deceleration comes from the `10 × kg`
term. With body fat known we model lean mass explicitly, assuming a **75/25
fat-to-lean split** of any weight change (`LeanShareOfWeightChange = 0.25`, the
standard rule of thumb for a moderate deficit):

```
lean(w)  = lean₀ + 0.25 × (w − w₀)
BMR(w)   = 370 + 21.6 × lean(w)        // slope 5.4 kcal/kg
```

vs. Mifflin's 10 kcal/kg. The curve still decelerates, but less steeply — which
is the point: a deficit that preserves lean mass preserves BMR.

**Refactor carried by this change:** `AdaptivePlanCurve`'s eight-parameter
signature is replaced by an injected `BMRModel func(weightKg float64) float64`,
built by `MifflinModel(sex, heightCm, age)` or `KatchMcArdleModel(w₀, bodyFatPct)`.
Fewer parameters, and the two formulas stay interchangeable at every call site.

## 4. Data Model

Migration `ensureBodyFatSchema`, registered last in the schema group of
`migrationSteps()` (before the data migrations):

```sql
ALTER TABLE weight_entries ADD COLUMN IF NOT EXISTS body_fat NUMERIC(4,1);
-- idempotent DO $$ … duplicate_object CHECK, matching ensureBodyProfileSchema:
--   weight_entries_body_fat_range: body_fat IS NULL OR (body_fat > 0 AND body_fat <= 75)
ALTER TABLE users ADD COLUMN IF NOT EXISTS body_fat_enabled BOOLEAN DEFAULT FALSE;
```

75 % is a deliberately loose upper bound (the highest values ever recorded are
~70 %); the parser enforces the same range so a bad value is a clean 400, never
a 500 from a constraint violation.

**Three-state upsert.** `POST /weight/upsert` must be able to set, clear, or
*leave alone* the body fat of an existing row — a weight-only save from another
client must not silently wipe a reading. Expressed as:

```go
// BodyFatUpdate is the three-state intent a weight upsert carries for the
// optional body-fat reading: absent key = leave it alone; present-and-null =
// clear it; present-and-numeric = set it.
type BodyFatUpdate struct {
    Set   bool     // false => preserve whatever is stored
    Value *float64 // nil with Set => clear
}
```

resolved in one statement (no read-modify-write race):

```sql
ON CONFLICT (user_id, entry_date) DO UPDATE SET
  weight   = EXCLUDED.weight,
  body_fat = CASE WHEN $5 THEN EXCLUDED.body_fat ELSE weight_entries.body_fat END,
  updated_at = NOW()
```

## 5. Backend

One new route; every other endpoint just gains a field:

| Endpoint | Change |
|---|---|
| `GET /weight/day` | `entry.body_fat` and `lastWeight.body_fat` in the payload |
| `POST /weight/upsert` | accepts optional `body_fat` with the three-state semantics above |
| `POST /entries` | accepts optional `body_fat` alongside `weight` (API/Android parity) |
| `GET /api/dashboard` | `weightEntry.body_fat`, `lastWeightEntry.body_fat` |
| `GET /api/plan` | new `composition`, `computed.bmrFormula`, and `bodyFat` on each series point |
| `POST /weight/toggle-body-fat` | **new** — sets `users.body_fat_enabled` (mirrors `/api/notes/toggle-enabled`) |
| `POST /settings/export` | `body_fat` on each exported weight row |
| `POST /settings/import` | parses `body_fat`; **auto-enables the flag** when any imported row has one, so imported data is immediately editable |
| `GET /api/me`, `GET /api/settings` | `bodyFatEnabled` on the user object |

New plan payload shape:

```go
type BodyComposition struct {
    Date       string   `json:"date"`       // when it was measured
    BodyFatPct float64  `json:"bodyFatPct"`
    LeanMass   float64  `json:"leanMass"`   // display unit, converted like every other weight
    FatMass    float64  `json:"fatMass"`
    Category   *string  `json:"category"`   // nil when sex is unknown
}
```

`PlanComputed` gains `bmrFormula string` (`"mifflin_st_jeor"` | `"katch_mcardle"`).
`ConvertPlanResponseToDisplayUnit` converts `LeanMass`/`FatMass` and leaves
`BodyFatPct` alone.

## 6. Frontend

1. **`WeightRow` (dashboard)** — when `bodyFatEnabled`, a second, narrower input
   with a `%` suffix beside the weight input. It is **disabled until the
   selected date has a weight entry**, with an explanatory title. That mirrors
   the DB shape and, more importantly, avoids the trap the existing weight input
   already guards against: the row pre-fills with the *last* weight, so
   accepting body fat first would silently write a stale weight to today. Same
   blur-to-save, same toast, same read-only rendering for linked users.
2. **Plan status header** — a fourth tile, **Body fat**: `24.3 %` + category
   chip, sub-line `62.3 kg lean · 20.0 kg fat`. Grid goes
   `sm:grid-cols-2 lg:grid-cols-4` when composition exists, unchanged otherwise.
3. **Recommended budget card** — one muted line naming the formula used, e.g.
   *"Based on Katch–McArdle from 62.3 kg lean mass"*. Makes the accuracy upgrade
   visible instead of silent.
4. **`PlanChart` (full variant only)** — an optional body-fat line on its **own
   right-hand % axis**, distinct hue, dotted (secondary encoding, per `dataviz`),
   with a legend entry. Skipped on the `spark` variant, which has no axes to
   disambiguate two scales.
5. **`BodyFatSettings`** — a "Track Body Fat" card beside Todos and Daily
   Notes, same heading + description + switch shape as those.

All strings via `react-i18next`, added to **all 8 locales** (de, en, es, fr, it,
nl, pl, pt).

## 7. Testing & Verification

- **Go unit** — `internal/service/bodycomp_test.go`: lean/fat mass, Katch–McArdle
  against known values (62.3 kg lean → 1715.7 kcal), every category band incl.
  boundaries and the unknown-sex case, `KatchMcArdleModel` slope.
- **Go unit** — `plan_assemble_test.go`: composition emitted; Katch–McArdle
  selected when body fat is present and Mifflin when it isn't (asserted against
  independently-computed literals, not by calling the same helper).
- **Go unit** — `weight_test.go`: the three-state `BodyFatUpdate` (preserve /
  set / clear) and `ParseBodyFat` bounds.
- **Go handler** — upsert validation: out-of-range → 400, absent key preserves.
- **Migration** — extend the idempotency integration test to assert both new
  columns.
- **e2e** — `e2e/bodyfat.spec.ts`: enable the preference → log weight → log body
  fat → assert persisted, then assert `/plan` shows the composition tile.
- **Build gates** — `go build ./...`, `go test ./...`, `cd client && npm run build`.
- **Run it** — bring up `compose.dev.yml`, drive the flow with real data, confirm
  the number is right and the chart renders, before calling this done.

## 8. Out of Scope

- Body-fat *goals* / target composition (own goal type, own guardrails).
- Estimating body fat from tape measurements (Navy/YMCA formulas) — a different
  input feature, not a different storage shape.
- Android app (separate repo); the API additions are additive so it can follow.
- Body-fat trend status badge — the chart line carries that signal.

## 9. Files Touched

**Backend** — `internal/database/migrations.go` (+`ensureBodyFatSchema`),
`internal/model/models.go` (`User.BodyFatEnabled`, `WeightEntry.BodyFat`),
`internal/middleware/auth.go` (SELECT/Scan), `internal/service/weight.go`
(`BodyFatUpdate`, upsert/read), `internal/service/utils.go` (`ParseBodyFat`),
`internal/service/bodycomp.go` (new), `internal/service/plan.go` (`BMRModel`,
curve refactor), `internal/service/plan_assemble.go` (composition + formula
selection), `internal/service/plan_units.go` (convert lean/fat mass),
`internal/service/weightgoal.go` (`GetWeightSeries` reads body fat),
`internal/handler/weight.go`, `internal/handler/entries.go`,
`internal/handler/entries_crud.go`, `internal/handler/entries_export.go`,
`internal/handler/plan.go`, `internal/handler/settings.go`,
`internal/handler/api.go`.

**Frontend** — `client/src/types/index.ts`, `client/src/api/weight.ts`,
`client/src/api/settings.ts`, `client/src/pages/Dashboard/WeightRow.tsx`,
`client/src/pages/Dashboard/Dashboard.tsx`,
`client/src/pages/Settings/BodyFatSettings.tsx` (new),
`client/src/pages/Settings/Settings.tsx`,
`client/src/pages/Plan/Plan.tsx`, `client/src/pages/Plan/PlanChart.tsx`,
`client/src/i18n/locales/*/{dashboard,settings}.json` (8 locales).

**Docs** — `README.md`, `CLAUDE.md`, `docs/api.md`,
`docs/manual-test-checklist.md`.

## 10. Verified

- `go build ./...`, `go vet ./...`, `go test ./...` — green.
- `npm run typecheck`, `npm run build`, `npm run test` (102 client tests),
  `npm run i18n:drift`, `npm run i18n:check` — green.
- Full Playwright suite against `compose.test.yml`: 236 passed. The one failure
  (`mobile-shell.spec.ts` "a new quick food is created with its values in one
  step") **reproduces on `staging` at 9d47d796**, which in fact fails two
  mobile-shell tests — it predates this branch.
- Driven live with 12 weeks of seeded data: 89.5 kg at 23.9 % → 68.1 kg lean →
  BMR 1841 → TDEE 2854 (moderate) → 2305 kcal/day at 0.5 kg/week. Mifflin for
  the same profile gives 2329, so the formula switch is visible and correct.
- Export/import round-trip asserted in `e2e/data-export-import.spec.ts`,
  including the omit-when-null and auto-enable-on-import behaviours.

**Deliberately not changed:** the chart draws one marker per logged day, so a
6-month history renders as a dense band of dots. That predates this work and
belongs to whoever revisits chart density.
