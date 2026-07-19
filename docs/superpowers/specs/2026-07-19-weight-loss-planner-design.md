# Weight-Loss Planner — Design Spec

**Date:** 2026-07-19
**Branch:** `worktree-weight-loss-planner` (off `staging`)
**Status:** Approved to implement (user delegated remaining decisions)

## 1. Problem & Goal

Schautrack tracks weight (per-day log) and calories/macros, but has **no
concept of a weight goal or a plan to reach it**. A user weighing 130 kg who
wants to reach 80 kg has no way to turn that into an actionable, safe plan.

This feature adds a **smart weight planner**: set a target weight + a pace,
and the app computes a personalized **daily calorie budget**, projects a
**timeline**, tracks **actual-vs-planned progress** from logged weight, and
feeds the recommended budget into the existing calorie goal — all with health
guardrails.

It ships to **all schautrack users** (it's a product feature, not a one-off
calculation).

## 2. Decisions (locked)

| Decision | Choice |
|---|---|
| Depth | Full smart planner: BMR/TDEE budget + timeline + trend analysis + chart + adaptation + guardrails |
| Calorie-goal wiring | **Suggest + one-click "Apply as my calorie goal"** — never silently overwrites |
| Pace input | **Both** — user picks *by rate* (kg/week or % bodyweight) OR *by target date*; planner solves for the other; clamp + warn if unsafe |
| Direction | General: supports loss, gain, and maintain (direction implied by target vs current) |
| Body metrics storage | New nullable columns on `users`: `height_cm`, `birth_year`, `sex`, `activity_level` |
| Goal storage | New `weight_goals` table, one `active` goal per user, history preserved |
| Calc location | **Server-side** pure functions (single source of truth, unit-tested). Client only renders. |
| Chart | **Dependency-free inline SVG**, theme-aware (no chart lib added) |
| Placement | New `/plan` page (nav link) + compact summary card on Dashboard + metrics edited inline on `/plan` |

**Alternatives considered & rejected:** client-side calc (no client test runner,
would duplicate for Android, drift risk); JSONB-on-user goal storage (works but a
table gives history + a clean partial-unique for "one active"); auto-syncing the
calorie goal (takes control away, mutates a manually-set field).

## 3. The Math (server, `internal/service/plan.go`)

All pure functions, table-driven tests in `plan_test.go` (mirrors
`macros_test.go`).

**Constants**
- `KcalPerKg = 7700`
- Activity factors: `sedentary 1.2`, `light 1.375`, `moderate 1.55`, `active 1.725`, `very_active 1.9`
- Calorie floors (safety): `male 1500`, `female 1200`, `other 1300`; additionally never recommend below BMR without a warning.
- Healthy loss/gain rate: recommend ≤ **1%/week** of current bodyweight; warn beyond.

**Formulas**
- **BMR** (Mifflin–St Jeor): `10*kg + 6.25*cm − 5*age + c`, where `c = +5 male, −161 female, −78 other` (neutral avg).
- **TDEE** = `BMR × activityFactor`.
- **Deficit/surplus for a rate**: `kcalPerDay = rateKgPerWeek × 7700 / 7`.
- **Budget** = `TDEE − deficit` (loss) or `TDEE + surplus` (gain), clamped to floor; if clamp binds, emit a "rate not achievable without going below a safe minimum" warning.
- **Rate for a target date**: `(startW − targetW) / weeksBetween(startDate, targetDate)`.
- **ETA**: `weeks = |current − target| / rateKgPerWeek` → date.
- **BMI** = `kg / (m²)`; category (underweight <18.5, normal 18.5–24.9, overweight 25–29.9, obese ≥30); **healthy weight range** for height = BMI 18.5–24.9 bounds.
- **Adaptive plan curve** `AdaptivePlanCurve(...)`: simulate week-by-week at the chosen budget, recomputing TDEE at each week's weight → realistic decelerating curve (cap ~3 yr / 160 weeks). This is the "plan" line on the chart.
- **Trend analysis** `TrendAnalysis(entries, windowDays)`: least-squares slope over recent weight points → actual kg/week + projected date at current pace + status vs plan (`ahead` / `on_track` / `behind` / `stalled`). Needs ≥2 points spanning ≥7 days; otherwise `insufficient_data`.

**Guardrail warnings surfaced to the UI** (non-blocking, advisory):
- rate > 1%/week ("aggressive — consider a slower pace")
- budget clamped to floor ("target date requires an unsafe deficit")
- target BMI < 18.5 ("target is in the underweight range")
- target BMI ≥ 30 for a gain goal ("target is in the obese range")
- Always: a "not medical advice" disclaimer.

**Graceful degradation:** if body metrics are incomplete, BMR/TDEE/budget are
omitted, but the planner still shows the **data-driven trend projection** from
weight history (the "learn maintenance from data" fallback). So the feature is
useful before metrics are filled in.

## 4. Data Model

### 4.1 Body metrics — columns on `users` (migration `ensureBodyProfileSchema`)
```sql
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS height_cm      NUMERIC(5,1),
  ADD COLUMN IF NOT EXISTS birth_year     SMALLINT,
  ADD COLUMN IF NOT EXISTS sex            TEXT,
  ADD COLUMN IF NOT EXISTS activity_level TEXT;
-- CHECK constraints (idempotent DO $$ … duplicate_object pattern):
--   height_cm  BETWEEN 50 AND 300
--   birth_year BETWEEN 1900 AND <currentYear-min-age>   (validate in handler; keep DB check loose: 1900..2200)
--   sex IN ('male','female','other')
--   activity_level IN ('sedentary','light','moderate','active','very_active')
```
Wired into `runAllMigrations` (parallel group) in `internal/database/migrations.go`.
Added to the `GetUserByID` SELECT + Scan in `internal/middleware/auth.go` and to
`model.User`.

`birth_year` (not full birth date) minimizes PII sensitivity; age ≈ currentYear −
birthYear (±1 yr is negligible for BMR).

### 4.2 Weight goal — new table (migration `ensureWeightGoalsSchema`)
```sql
CREATE TABLE IF NOT EXISTS weight_goals (
  id               SERIAL PRIMARY KEY,
  user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  start_weight     NUMERIC(6,2) NOT NULL,
  start_date       DATE NOT NULL,
  target_weight    NUMERIC(6,2) NOT NULL,
  pace_mode        TEXT NOT NULL CHECK (pace_mode IN ('rate','date')),
  rate_kg_per_week NUMERIC(4,2),          -- set when pace_mode='rate' (magnitude > 0)
  target_date      DATE,                  -- set when pace_mode='date'
  activity_level   TEXT,                  -- snapshot at creation
  status           TEXT NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active','achieved','abandoned')),
  achieved_at      TIMESTAMPTZ,
  created_at       TIMESTAMPTZ DEFAULT NOW(),
  updated_at       TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT weight_goals_positive CHECK (start_weight > 0 AND target_weight > 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS weight_goals_one_active_idx
  ON weight_goals (user_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS weight_goals_user_idx ON weight_goals (user_id);
```

## 5. Backend API (`internal/handler/plan.go`, routes in `cmd/server/main.go`)

Follow existing conventions: `middleware.RequireLogin` on all; `session.CsrfProtection`
on mutations; `JSON`/`ErrorJSON` helpers; broadcast via `sse.Broker` where a
change affects the dashboard.

| Method | Path | Purpose |
|---|---|---|
| `GET`  | `/plan` | Full payload: metrics, active goal, computed `{bmr,tdee,budget,eta,planCurve,trend,bmi,healthyRange,warnings}`, current weight, recent weight series (last N days, default 180) |
| `PUT`  | `/plan/metrics` | Update `height_cm, birth_year, sex, activity_level` (validated) |
| `PUT`  | `/plan/goal` | Create/replace the active goal (start snapshot = latest logged weight or provided) |
| `POST` | `/plan/goal/apply-budget` | Set `macro_goals.calories` = computed budget (reuse the settings.go macro-goal update path); broadcast entry change |
| `POST` | `/plan/goal/abandon` | Set active goal `status='abandoned'` |

`GET /plan` computes everything server-side so the client is a pure renderer.
Auto-mark `status='achieved'` (+ `achieved_at`) when current weight crosses the
target, detected on `GET /plan`.

New user fields exposed in `Me`/`Settings` payloads (`internal/handler/api.go`)
so the client `User` type carries metrics.

**Services:** `internal/service/plan.go` (math, above) + `internal/service/weightgoal.go`
(CRUD: `GetActiveGoal`, `UpsertActiveGoal`, `AbandonGoal`, `MarkAchieved`; body-metric
read/write helpers).

## 6. Frontend (`client/`)

**New route `/plan`** (protected) in `router.tsx`; **nav link "Plan"** in
`Header.tsx` (between Dashboard and Settings).

**`client/src/pages/Plan/Plan.tsx`** — sections:
1. **Status header** — current weight, BMI + category chip, healthy-weight range.
2. **Your details** (inline, collapsible) — height, age/birth-year, sex, activity level. Shown expanded when incomplete. `PUT /plan/metrics`.
3. **Goal setup** — target weight; pace toggle *By rate* ↔ *By date*; live-computed budget, ETA, and warnings as they type. `PUT /plan/goal`.
4. **Recommended budget** — big number + `Apply as my calorie goal` button showing current goal for comparison. `POST /plan/goal/apply-budget`.
5. **Chart** (`PlanChart.tsx`) — dependency-free inline SVG, theme-aware (per `dataviz` skill): actual weight points, smoothed trend line, adaptive plan curve, target line, healthy-range band. Responsive; wide content scroll-safe.
6. **Progress** — % to goal, on-track/ahead/behind/stalled badge from trend analysis, projected date.
7. **Disclaimer** — "Estimates only, not medical advice."

**`client/src/pages/Dashboard/PlanCard.tsx`** — compact card (only if an active
goal exists): current → target, % progress, on-track badge, sparkline, link to
`/plan`. Fetches `/plan` via its own TanStack Query (lazy; no change to the
dashboard payload).

**`client/src/api/plan.ts`** — `getPlan`, `updateMetrics`, `upsertGoal`,
`applyBudget`, `abandonGoal`. **Types** added to `client/src/types/index.ts`
(extend `User` with metrics; add `Plan`, `WeightGoal`, `PlanComputed`).

Respect `weightUnit` (kg/lb) everywhere: store canonical kg server-side, convert
for display/input like existing weight UI.

## 7. Testing & Verification (quality gate — end-to-end)

- **Go unit:** `internal/service/plan_test.go` — BMR/TDEE/budget/rate/ETA/BMI/
  healthy-range/adaptive-curve/trend/guardrails (table-driven). Known-value checks
  (e.g. 130 kg / 180 cm / 40 yr / male / moderate → BMR = 2 230, TDEE ≈ 3 456;
  at 0.75 kg/week the deficit is 825 kcal → budget ≈ 2 631 kcal; BMI 130 @ 180 cm ≈ 40.1).
- **Go handler:** `plan_test.go` for the 5 endpoints (auth required, validation,
  apply-budget writes `macro_goals.calories`, one-active-goal invariant) following
  `entries_test.go`/`settings_test.go`.
- **Migration:** idempotent (runs twice cleanly), following `migrations_test.go`.
- **e2e (Playwright):** `e2e/plan.spec.ts` happy path — set metrics → set goal by
  rate → see budget → apply → assert dashboard calorie goal updated; and by-date →
  warning shown. (Client has no unit-test runner, so behavior is covered here.)
- **Build:** `go build ./...`, `go test ./...`, `cd client && npm run build` (tsc).
- **Run it:** bring the stack up (`compose.dev.yml`) and drive the flow with real
  data before declaring done. Verify budget number is sane, apply changes the
  dashboard goal, chart renders in light + dark.

## 8. Out of Scope

- Android app (separate repo) — server API is clean so it can follow later.
- Multiple concurrent goals; macro-split planning; exercise/calories-burned input.
- Privacy-policy copy update for the new health fields (flag to user; not code).

## 9. Files Touched (map for implementers)

**Backend**
- `internal/database/migrations.go` — add `ensureBodyProfileSchema`, `ensureWeightGoalsSchema`; register in `runAllMigrations`.
- `internal/model/models.go` — `User` gets `HeightCm *float64`, `BirthYear *int`, `Sex *string`, `ActivityLevel *string`; new `WeightGoal` struct.
- `internal/middleware/auth.go` — extend `GetUserByID` SELECT + Scan.
- `internal/service/plan.go` (+ `plan_test.go`) — the math.
- `internal/service/weightgoal.go` — goal + metrics persistence.
- `internal/handler/plan.go` (+ `plan_test.go`) — 5 endpoints.
- `internal/handler/api.go` — expose metrics in `Me`/`Settings`.
- `cmd/server/main.go` — construct `PlanHandler`, register routes (near the weight routes ~L222).

**Frontend**
- `client/src/router.tsx` — `/plan` route.
- `client/src/components/Layout/Header.tsx` — nav link.
- `client/src/pages/Plan/Plan.tsx`, `client/src/pages/Plan/PlanChart.tsx`.
- `client/src/pages/Dashboard/PlanCard.tsx` + mount in `Dashboard.tsx`.
- `client/src/api/plan.ts`; `client/src/types/index.ts`.

**Tests/docs**
- `e2e/plan.spec.ts`; update `README.md` feature list.
