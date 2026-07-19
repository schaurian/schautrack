# Weight-Loss Planner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a schautrack user turn a target weight into a safe, personalized plan — a daily calorie budget, a projected timeline, and actual-vs-planned progress — and apply the recommended budget to their calorie goal with one click.

**Architecture:** All math and projections are pure Go functions in `internal/service/plan.go` (single source of truth, fully unit-tested). Body metrics live as nullable columns on `users`; the goal lives in a new `weight_goals` table (one active per user). A `PlanHandler` exposes 5 endpoints; `GET /plan` returns a fully-computed payload so the React client is a pure renderer. The client adds a `/plan` page (metrics form, goal setup, budget apply, dependency-free SVG chart) and a compact Dashboard summary card.

**Tech Stack:** Go 1.24 (chi, pgx v5), Postgres; React 19 + react-router 8 + TanStack Query + Zustand + Tailwind 4 (lucide-react icons); Playwright for e2e. **No new dependencies.**

## Global Constraints

- **No new runtime dependencies** (server or client). Chart is hand-rolled inline SVG.
- **No `latest`/floating anything**; follow existing versions.
- Conventional-commit messages (`feat:`, `test:`, `docs:`…); commit after every green step.
- Weight stored canonically in **kg** server-side; convert for display per `user.weightUnit` (`kg`/`lb`), mirroring existing `WeightRow.tsx`.
- Migrations must be **idempotent** (`ADD COLUMN IF NOT EXISTS`, `DO $$ … duplicate_object` for constraints) and wired into `runAllMigrations` in `internal/database/migrations.go`.
- All new HTTP routes require `middleware.RequireLogin`; mutations also require `session.CsrfProtection`. Use `JSON`/`ErrorJSON` helpers.
- Calc constants (locked): `KcalPerKg=7700`; activity factors sedentary 1.2 / light 1.375 / moderate 1.55 / active 1.725 / very_active 1.9; calorie floors male 1500 / female 1200 / other 1300 / unknown 1200; healthy rate ≤ 1%/week of current bodyweight.
- Mifflin–St Jeor constant `c`: male +5, female −161, other −78.
- Reference values (for tests): 130 kg / 180 cm / age 40 / male / moderate → BMR = 2230, TDEE ≈ 3456; at 0.75 kg/week deficit = 825 → budget ≈ 2631; BMI 130 @ 180 cm ≈ 40.1.

---

## Task 1: Schema, models, user scan

**Files:**
- Modify: `internal/database/migrations.go` (add two `ensureX` funcs + register in `runAllMigrations`)
- Modify: `internal/database/migrations_test.go` (idempotency assertion for new columns/table)
- Modify: `internal/model/models.go` (User fields + `WeightGoal` struct)
- Modify: `internal/middleware/auth.go` (extend `GetUserByID` SELECT + Scan)

**Interfaces:**
- Produces: `users.height_cm NUMERIC(5,1)`, `users.birth_year SMALLINT`, `users.sex TEXT`, `users.activity_level TEXT`; table `weight_goals` (schema per spec §4.2). `model.User` gains `HeightCm *float64`, `BirthYear *int`, `Sex *string`, `ActivityLevel *string`. New `model.WeightGoal`.

- [ ] **Step 1: Add body-profile migration.** In `internal/database/migrations.go`, add:
```go
func ensureBodyProfileSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return withTransaction(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			ALTER TABLE users
				ADD COLUMN IF NOT EXISTS height_cm      NUMERIC(5,1),
				ADD COLUMN IF NOT EXISTS birth_year     SMALLINT,
				ADD COLUMN IF NOT EXISTS sex            TEXT,
				ADD COLUMN IF NOT EXISTS activity_level TEXT`); err != nil {
			return err
		}
		checks := []struct{ name, expr string }{
			{"users_height_cm_range", "height_cm IS NULL OR (height_cm >= 50 AND height_cm <= 300)"},
			{"users_birth_year_range", "birth_year IS NULL OR (birth_year >= 1900 AND birth_year <= 2200)"},
			{"users_sex_valid", "sex IS NULL OR sex IN ('male','female','other')"},
			{"users_activity_valid", "activity_level IS NULL OR activity_level IN ('sedentary','light','moderate','active','very_active')"},
		}
		for _, c := range checks {
			if _, err := tx.Exec(ctx, fmt.Sprintf(`
				DO $$ BEGIN
					ALTER TABLE users ADD CONSTRAINT %s CHECK (%s);
				EXCEPTION WHEN duplicate_object THEN NULL;
				END $$`, c.name, c.expr)); err != nil {
				return err
			}
		}
		return nil
	})
}
```

- [ ] **Step 2: Add weight-goals migration.** Add `ensureWeightGoalsSchema` with the exact DDL from spec §4.2 (table + `weight_goals_one_active_idx` partial unique index + `weight_goals_user_idx`).

- [ ] **Step 3: Register both** in `runAllMigrations`'s parallel `migrations` slice: `{"body_profile", ensureBodyProfileSchema}` and `{"weight_goals", ensureWeightGoalsSchema}`.

- [ ] **Step 4: Extend model.** In `internal/model/models.go`, add to `User`:
```go
	HeightCm      *float64 `json:"height_cm,omitempty"`
	BirthYear     *int     `json:"birth_year,omitempty"`
	Sex           *string  `json:"sex,omitempty"`
	ActivityLevel *string  `json:"activity_level,omitempty"`
```
and a new struct:
```go
type WeightGoal struct {
	ID            int        `json:"id"`
	UserID        int        `json:"user_id"`
	StartWeight   float64    `json:"start_weight"`
	StartDate     string     `json:"start_date"`
	TargetWeight  float64    `json:"target_weight"`
	PaceMode      string     `json:"pace_mode"` // "rate" | "date"
	RateKgPerWeek *float64   `json:"rate_kg_per_week,omitempty"`
	TargetDate    *string    `json:"target_date,omitempty"`
	ActivityLevel *string    `json:"activity_level,omitempty"`
	Status        string     `json:"status"`
	AchievedAt    *time.Time `json:"achieved_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}
```

- [ ] **Step 5: Extend user scan.** In `internal/middleware/auth.go` `GetUserByID`, add the 4 columns to the SELECT list and 4 pointers to `.Scan(...)` (append `height_cm, birth_year, sex, activity_level` after `notes_enabled`; scan into `&u.HeightCm, &u.BirthYear, &u.Sex, &u.ActivityLevel`).

- [ ] **Step 6: Migration idempotency test.** In `migrations_test.go`, follow the existing test-pool pattern: run `runAllMigrations` twice against the test DB, assert no error, and assert `weight_goals` exists + `users.height_cm` column exists (query `information_schema.columns`).

- [ ] **Step 7: Verify.** Run `go build ./...` then `go test ./internal/database/...`. Expected: PASS.

- [ ] **Step 8: Commit.** `git add -A && git commit -m "feat(plan): add body-metric columns and weight_goals table"`

---

## Task 2: Plan math service (pure, TDD)

**Files:**
- Create: `internal/service/plan.go`
- Create: `internal/service/plan_test.go`

**Interfaces:**
- Produces (all in package `service`): types `Sex`, `ActivityLevel`, `Direction`, `CurvePoint{Week int; Weight float64}`, `WeightPoint{Date time.Time; Weight float64}`, `Trend{SlopeKgPerWeek float64; HasData bool; ProjectedWeeks float64; Status string}`, `PlanWarning{Code, Message string}`; funcs `BMR(sex Sex, weightKg, heightCm float64, ageYears int) float64`, `TDEE(bmr float64, a ActivityLevel) float64`, `ActivityFactor(a ActivityLevel) float64`, `DailyDeficitForRate(rateKgPerWeek float64) float64`, `GoalDirection(startW, targetW float64) Direction`, `CalorieFloor(sex Sex) float64`, `RecommendedBudget(tdee, rateKgPerWeek float64, dir Direction, floor float64) (kcal int, clamped bool)`, `RateForDate(startW, targetW float64, startDate, targetDate time.Time) float64`, `ETAWeeks(currentW, targetW, rateKgPerWeek float64) float64`, `BMI(weightKg, heightCm float64) float64`, `BMICategory(bmi float64) string`, `HealthyWeightRange(heightCm float64) (minKg, maxKg float64)`, `AdaptivePlanCurve(startW, targetW, budgetKcal float64, sex Sex, heightCm float64, ageYears int, a ActivityLevel, maxWeeks int) []CurvePoint`, `TrendAnalysis(points []WeightPoint, targetW, planRateKgPerWeek float64, windowDays int, now time.Time) Trend`, `RateSharePerWeek(rateKgPerWeek, currentW float64) float64`.

- [ ] **Step 1: Write failing tests** in `internal/service/plan_test.go` (table-driven, mirror `macros_test.go`):
```go
package service

import (
	"math"
	"testing"
	"time"
)

func almost(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

func TestBMR(t *testing.T) {
	got := BMR(SexMale, 130, 180, 40)
	if !almost(got, 2230, 0.5) {
		t.Fatalf("BMR male = %v, want 2230", got)
	}
	if got := BMR(SexFemale, 80, 165, 30); !almost(got, 1520.25, 0.5) {
		t.Fatalf("BMR female = %v, want 1520.25", got)
	}
	if got := BMR(SexMale, 0, 180, 40); got != 0 {
		t.Fatalf("BMR with 0 weight = %v, want 0", got)
	}
}

func TestTDEE(t *testing.T) {
	if got := TDEE(2230, ActivityModerate); !almost(got, 3456.5, 0.5) {
		t.Fatalf("TDEE = %v, want 3456.5", got)
	}
}

func TestRecommendedBudget(t *testing.T) {
	// TDEE 3456.5 - deficit(0.75) 825 = 2631.5 -> 2631 or 2632 after round; assert range
	kcal, clamped := RecommendedBudget(3456.5, 0.75, DirLoss, 1500)
	if clamped || kcal < 2630 || kcal > 2632 {
		t.Fatalf("budget = %d clamped=%v, want ~2631 unclamped", kcal, clamped)
	}
	// Aggressive deficit clamps to floor
	kcal, clamped = RecommendedBudget(1800, 1.0, DirLoss, 1500)
	if !clamped || kcal != 1500 {
		t.Fatalf("budget = %d clamped=%v, want 1500 clamped", kcal, clamped)
	}
	// Gain adds surplus
	if kcal, _ := RecommendedBudget(2000, 0.5, DirGain, 1200); kcal <= 2000 {
		t.Fatalf("gain budget = %d, want > 2000", kcal)
	}
}

func TestRateForDateAndETA(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 1, 29, 0, 0, 0, 0, time.UTC) // 4 weeks
	if got := RateForDate(100, 96, start, end); !almost(got, 1.0, 1e-9) {
		t.Fatalf("RateForDate = %v, want 1.0", got)
	}
	if got := ETAWeeks(100, 80, 0.5); !almost(got, 40, 1e-9) {
		t.Fatalf("ETAWeeks = %v, want 40", got)
	}
	if got := ETAWeeks(100, 80, 0); !math.IsInf(got, 1) {
		t.Fatalf("ETAWeeks rate 0 = %v, want +Inf", got)
	}
}

func TestBMI(t *testing.T) {
	if got := BMI(130, 180); !almost(got, 40.1, 0.05) {
		t.Fatalf("BMI = %v, want 40.1", got)
	}
	if BMICategory(40.1) != "obese" || BMICategory(22) != "normal" || BMICategory(17) != "underweight" || BMICategory(27) != "overweight" {
		t.Fatalf("BMICategory mismatch")
	}
	lo, hi := HealthyWeightRange(180)
	if !almost(lo, 59.9, 0.5) || !almost(hi, 80.7, 0.5) {
		t.Fatalf("HealthyWeightRange = %v..%v, want ~59.9..80.7", lo, hi)
	}
}

func TestAdaptivePlanCurve(t *testing.T) {
	curve := AdaptivePlanCurve(130, 80, 2200, SexMale, 180, 40, ActivityModerate, 200)
	if len(curve) < 2 || curve[0].Weight != 130 {
		t.Fatalf("curve start wrong: %+v", curve[:1])
	}
	if last := curve[len(curve)-1]; last.Weight > 80.5 {
		t.Fatalf("curve did not reach target: end %v", last.Weight)
	}
	// Deceleration: first week's drop > a later week's drop
	d0 := curve[0].Weight - curve[1].Weight
	dN := curve[len(curve)-2].Weight - curve[len(curve)-1].Weight
	if d0 <= dN {
		t.Fatalf("expected decelerating loss: d0=%v dN=%v", d0, dN)
	}
}

func TestTrendAnalysis(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	pts := []WeightPoint{
		{now.AddDate(0, 0, -21), 132},
		{now.AddDate(0, 0, -14), 131},
		{now.AddDate(0, 0, -7), 130},
		{now, 129},
	}
	tr := TrendAnalysis(pts, 80, 0.75, 30, now)
	if !tr.HasData || tr.SlopeKgPerWeek > -0.9 || tr.SlopeKgPerWeek < -1.1 {
		t.Fatalf("slope = %v, want ~-1.0/wk", tr.SlopeKgPerWeek)
	}
	if tr.Status != "ahead" && tr.Status != "on_track" {
		t.Fatalf("status = %q, want ahead/on_track", tr.Status)
	}
	if got := TrendAnalysis(pts[:1], 80, 0.75, 30, now); got.Status != "insufficient_data" {
		t.Fatalf("single point status = %q, want insufficient_data", got.Status)
	}
}
```

- [ ] **Step 2: Run to confirm failure.** `go test ./internal/service/ -run 'TestBMR|TestTDEE|TestRecommendedBudget|TestRateForDate|TestBMI|TestAdaptive|TestTrend' -v` → FAIL (undefined).

- [ ] **Step 3: Implement `internal/service/plan.go`.** Full implementation:
```go
package service

import (
	"math"
	"time"
)

type Sex string

const (
	SexMale   Sex = "male"
	SexFemale Sex = "female"
	SexOther  Sex = "other"
)

type ActivityLevel string

const (
	ActivitySedentary  ActivityLevel = "sedentary"
	ActivityLight      ActivityLevel = "light"
	ActivityModerate   ActivityLevel = "moderate"
	ActivityActive     ActivityLevel = "active"
	ActivityVeryActive ActivityLevel = "very_active"
)

type Direction string

const (
	DirLoss     Direction = "loss"
	DirGain     Direction = "gain"
	DirMaintain Direction = "maintain"
)

const KcalPerKg = 7700.0

var activityFactors = map[ActivityLevel]float64{
	ActivitySedentary: 1.2, ActivityLight: 1.375, ActivityModerate: 1.55,
	ActivityActive: 1.725, ActivityVeryActive: 1.9,
}

func ActivityFactor(a ActivityLevel) float64 { return activityFactors[a] } // 0 if unknown

// BMR uses Mifflin–St Jeor. Returns 0 if any input is non-positive.
func BMR(sex Sex, weightKg, heightCm float64, ageYears int) float64 {
	if weightKg <= 0 || heightCm <= 0 || ageYears <= 0 {
		return 0
	}
	c := -78.0 // "other" neutral average
	switch sex {
	case SexMale:
		c = 5
	case SexFemale:
		c = -161
	}
	return 10*weightKg + 6.25*heightCm - 5*float64(ageYears) + c
}

func TDEE(bmr float64, a ActivityLevel) float64 {
	f := ActivityFactor(a)
	if f == 0 {
		f = 1.2 // conservative default when unknown
	}
	return bmr * f
}

func DailyDeficitForRate(rateKgPerWeek float64) float64 {
	return math.Abs(rateKgPerWeek) * KcalPerKg / 7
}

func GoalDirection(startW, targetW float64) Direction {
	switch {
	case targetW < startW:
		return DirLoss
	case targetW > startW:
		return DirGain
	default:
		return DirMaintain
	}
}

func CalorieFloor(sex Sex) float64 {
	switch sex {
	case SexMale:
		return 1500
	case SexFemale:
		return 1200
	case SexOther:
		return 1300
	default:
		return 1200
	}
}

// RecommendedBudget returns the daily kcal target and whether it was clamped to floor.
func RecommendedBudget(tdee, rateKgPerWeek float64, dir Direction, floor float64) (int, bool) {
	delta := DailyDeficitForRate(rateKgPerWeek)
	var budget float64
	switch dir {
	case DirGain:
		budget = tdee + delta
	case DirMaintain:
		budget = tdee
	default:
		budget = tdee - delta
	}
	clamped := false
	if budget < floor {
		budget = floor
		clamped = true
	}
	return int(math.Round(budget)), clamped
}

func RateForDate(startW, targetW float64, startDate, targetDate time.Time) float64 {
	weeks := targetDate.Sub(startDate).Hours() / (24 * 7)
	if weeks <= 0 {
		return math.Inf(1)
	}
	return math.Abs(startW-targetW) / weeks
}

func ETAWeeks(currentW, targetW, rateKgPerWeek float64) float64 {
	if rateKgPerWeek <= 0 {
		return math.Inf(1)
	}
	return math.Abs(currentW-targetW) / rateKgPerWeek
}

func BMI(weightKg, heightCm float64) float64 {
	if heightCm <= 0 {
		return 0
	}
	m := heightCm / 100
	return weightKg / (m * m)
}

func BMICategory(bmi float64) string {
	switch {
	case bmi < 18.5:
		return "underweight"
	case bmi < 25:
		return "normal"
	case bmi < 30:
		return "overweight"
	default:
		return "obese"
	}
}

func HealthyWeightRange(heightCm float64) (float64, float64) {
	m := heightCm / 100
	return 18.5 * m * m, 24.9 * m * m
}

func RateSharePerWeek(rateKgPerWeek, currentW float64) float64 {
	if currentW <= 0 {
		return 0
	}
	return math.Abs(rateKgPerWeek) / currentW
}

type CurvePoint struct {
	Week   int     `json:"week"`
	Weight float64 `json:"weight"`
}

// AdaptivePlanCurve simulates weekly weight at a fixed budget, recomputing TDEE
// as weight changes (realistic decelerating curve). Stops at target or maxWeeks.
func AdaptivePlanCurve(startW, targetW, budgetKcal float64, sex Sex, heightCm float64, ageYears int, a ActivityLevel, maxWeeks int) []CurvePoint {
	if maxWeeks <= 0 {
		maxWeeks = 160
	}
	dir := GoalDirection(startW, targetW)
	pts := []CurvePoint{{Week: 0, Weight: round1(startW)}}
	w := startW
	for wk := 1; wk <= maxWeeks; wk++ {
		tdee := TDEE(BMR(sex, w, heightCm, ageYears), a)
		dailyDelta := budgetKcal - tdee                 // <0 => losing
		weeklyKg := dailyDelta * 7 / KcalPerKg          // signed kg change
		w += weeklyKg
		if w < 30 {
			w = 30
		}
		pts = append(pts, CurvePoint{Week: wk, Weight: round1(w)})
		if (dir == DirLoss && w <= targetW) || (dir == DirGain && w >= targetW) {
			break
		}
		if math.Abs(weeklyKg) < 0.01 { // plateau — won't reach target
			break
		}
	}
	return pts
}

type WeightPoint struct {
	Date   time.Time
	Weight float64
}

type Trend struct {
	SlopeKgPerWeek float64 `json:"slope_kg_per_week"`
	HasData        bool    `json:"has_data"`
	ProjectedWeeks float64 `json:"projected_weeks"` // to target; -1 if not projectable
	Status         string  `json:"status"`
}

// TrendAnalysis fits a least-squares line over points within windowDays of now.
func TrendAnalysis(points []WeightPoint, targetW, planRateKgPerWeek float64, windowDays int, now time.Time) Trend {
	cutoff := now.AddDate(0, 0, -windowDays)
	var xs, ys []float64
	var t0 time.Time
	for _, p := range points {
		if p.Date.Before(cutoff) {
			continue
		}
		if t0.IsZero() {
			t0 = p.Date
		}
		xs = append(xs, p.Date.Sub(t0).Hours()/24) // days
		ys = append(ys, p.Weight)
	}
	if len(xs) < 2 || xs[len(xs)-1]-xs[0] < 7 {
		return Trend{HasData: false, ProjectedWeeks: -1, Status: "insufficient_data"}
	}
	slopePerDay := leastSquaresSlope(xs, ys)
	slopePerWeek := slopePerDay * 7
	tr := Trend{SlopeKgPerWeek: slopePerWeek, HasData: true, ProjectedWeeks: -1}

	dir := GoalDirection(ys[len(ys)-1], targetW)
	progressing := (dir == DirLoss && slopePerWeek < 0) || (dir == DirGain && slopePerWeek > 0)
	switch {
	case math.Abs(slopePerWeek) < 0.05:
		tr.Status = "stalled"
	case !progressing:
		tr.Status = "wrong_direction"
	default:
		tr.ProjectedWeeks = math.Abs(ys[len(ys)-1]-targetW) / math.Abs(slopePerWeek)
		ratio := math.Abs(slopePerWeek) / math.Max(planRateKgPerWeek, 1e-9)
		switch {
		case ratio >= 1.1:
			tr.Status = "ahead"
		case ratio >= 0.85:
			tr.Status = "on_track"
		default:
			tr.Status = "behind"
		}
	}
	return tr
}

func leastSquaresSlope(xs, ys []float64) float64 {
	n := float64(len(xs))
	var sx, sy, sxx, sxy float64
	for i := range xs {
		sx += xs[i]
		sy += ys[i]
		sxx += xs[i] * xs[i]
		sxy += xs[i] * ys[i]
	}
	den := n*sxx - sx*sx
	if den == 0 {
		return 0
	}
	return (n*sxy - sx*sy) / den
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

type PlanWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
```

- [ ] **Step 4: Run tests.** `go test ./internal/service/ -run 'BMR|TDEE|Budget|RateForDate|BMI|Adaptive|Trend' -v` → PASS. Then full `go test ./internal/service/`.

- [ ] **Step 5: Commit.** `git commit -am "feat(plan): add pure BMR/TDEE/budget/trend calculation service"`

---

## Task 3: Plan persistence + handlers + routes

**Files:**
- Create: `internal/service/weightgoal.go` (DB CRUD + metrics helpers)
- Create: `internal/handler/plan.go` (`PlanHandler`, 5 endpoints, payload assembly)
- Create: `internal/handler/plan_test.go` (handler tests — copy harness from `internal/handler/entries_test.go`)
- Modify: `cmd/server/main.go` (construct handler + register routes near L222)
- Modify: `internal/handler/api.go` (`Me` + `Settings` payloads expose metrics)

**Interfaces:**
- Consumes: everything from Task 2; `service.UpsertWeightEntry`/`GetLastWeightEntry` (existing); `model.WeightGoal`.
- Produces routes: `GET /plan`, `PUT /plan/metrics`, `PUT /plan/goal`, `POST /plan/goal/apply-budget`, `POST /plan/goal/abandon`. `GET /plan` JSON shape per spec §5 (keys: `metrics{heightCm,birthYear,sex,activityLevel,complete}`, `currentWeight`, `bmi`, `bmiCategory`, `healthyRange{minKg,maxKg}`, `goal`, `computed{bmr,tdee,budgetKcal,budgetClamped,rateKgPerWeek,etaWeeks,etaDate,planCurve}`, `trend{slopeKgPerWeek,hasData,projectedWeeks,projectedDate,status}`, `currentCalorieGoal`, `series[{date,weight}]`, `warnings[]`, `disclaimer`).

- [ ] **Step 1: weightgoal.go service.** Implement DB helpers (use `*pgxpool.Pool`, mirror `weight.go` style):
  - `GetActiveGoal(ctx, pool, userID) (*model.WeightGoal, error)` — `SELECT … WHERE user_id=$1 AND status='active' LIMIT 1`; `nil,nil` on no rows.
  - `UpsertActiveGoal(ctx, pool, g *model.WeightGoal) (*model.WeightGoal, error)` — in a tx: `UPDATE weight_goals SET status='abandoned', updated_at=NOW() WHERE user_id=$1 AND status='active'` then `INSERT … RETURNING *`. (Guarantees the one-active invariant.)
  - `AbandonActiveGoal(ctx, pool, userID) error`.
  - `MarkGoalAchieved(ctx, pool, goalID int) error` — `SET status='achieved', achieved_at=NOW()`.
  - `UpdateBodyMetrics(ctx, pool, userID int, heightCm *float64, birthYear *int, sex, activity *string) error` — `UPDATE users SET height_cm=$2, birth_year=$3, sex=$4, activity_level=$5 WHERE id=$1`.
  - `GetWeightSeries(ctx, pool, userID int, sinceDate string) ([]service.WeightPoint, error)` — `SELECT entry_date, weight FROM weight_entries WHERE user_id=$1 AND entry_date>=$2 ORDER BY entry_date`.

- [ ] **Step 2: Handler skeleton + GET /plan.** In `internal/handler/plan.go`:
```go
type PlanHandler struct {
	Pool   *pgxpool.Pool
	Broker *sse.Broker
}
```
`GET /plan` logic: load user via `middleware.GetCurrentUser`; compute age = `time.Now().Year() - *user.BirthYear` (if set); current weight via `service.GetLastWeightEntry(...,"")`; `series` via `GetWeightSeries` (last 180 days); active goal via `GetActiveGoal`. Compute BMI/category/healthyRange if height+weight present. If goal active + metrics complete (height, birthYear, sex, activity all non-nil): derive `rate` (goal.RateKgPerWeek or `RateForDate`), `dir=GoalDirection(current,target)`, `bmr/tdee`, `RecommendedBudget`, `ETAWeeks`+etaDate, `AdaptivePlanCurve`. `trend` via `TrendAnalysis(series, target, rate, 30, now)`. Auto-achieve: if goal active and direction target reached (current<=target for loss / >= for gain), call `MarkGoalAchieved` and reflect status. `currentCalorieGoal`: parse `macro_goals.calories` (fallback `daily_goal`). Assemble `warnings` (rate>1%/wk, budgetClamped, target BMI<18.5, gain target BMI>=30). Include `disclaimer` constant string. Return via `JSON`.

- [ ] **Step 3: PUT /plan/metrics.** Read JSON `{height_cm, birth_year, sex, activity_level}`; validate (height 50–300, birth_year 1900..currentYear-10, sex/activity in allowed sets — else `ErrorJSON 400`); `UpdateBodyMetrics`; return `{ok:true}`.

- [ ] **Step 4: PUT /plan/goal.** Read `{target_weight, pace_mode, rate_kg_per_week?, target_date?}`; validate (`target_weight`>0; `pace_mode` in {rate,date}; rate>0 when rate mode; valid future date when date mode); `start_weight` = latest logged weight (400 if none), `start_date` = today (user tz via `getUserTimezone`). Snapshot `activity_level` from user. `UpsertActiveGoal`; broadcast; return the goal.

- [ ] **Step 5: apply-budget + abandon.** `POST /plan/goal/apply-budget`: recompute budget (same as GET), write it into `macro_goals.calories` reusing the update SQL from `internal/handler/settings.go:122` (read current `macro_goals`, set `calories`, `UPDATE users SET macro_goals=$1`); broadcast `BroadcastEntryChange`; return `{ok, budget}`. `POST /plan/goal/abandon`: `AbandonActiveGoal`; return `{ok:true}`.

- [ ] **Step 6: Routes.** In `cmd/server/main.go` after the weight routes (~L225):
```go
planHandler := &handler.PlanHandler{Pool: pool, Broker: sseBroker}
r.With(middleware.RequireLogin).Get("/plan", planHandler.Get)
r.With(middleware.RequireLogin, session.CsrfProtection).Put("/plan/metrics", planHandler.UpdateMetrics)
r.With(middleware.RequireLogin, session.CsrfProtection).Put("/plan/goal", planHandler.UpsertGoal)
r.With(middleware.RequireLogin, session.CsrfProtection).Post("/plan/goal/apply-budget", planHandler.ApplyBudget)
r.With(middleware.RequireLogin, session.CsrfProtection).Post("/plan/goal/abandon", planHandler.AbandonGoal)
```
(Confirm these sit under the same `/api` mount as `/weight/*`.)

- [ ] **Step 7: Expose metrics in Me/Settings.** In `internal/handler/api.go`, add `"heightCm": user.HeightCm, "birthYear": user.BirthYear, "sex": user.Sex, "activityLevel": user.ActivityLevel` to both the `Me` (~L90) and `Settings` (~L156) user maps.

- [ ] **Step 8: Handler tests.** In `plan_test.go`, copy the auth/test-pool setup from `entries_test.go`; cover: (a) `GET /plan` unauth → 401; (b) set metrics then `GET /plan` returns bmr/tdee; (c) `PUT /plan/goal` by rate, then `GET` returns budget + planCurve non-empty; (d) `apply-budget` sets `macro_goals.calories` (assert via DB); (e) second `PUT /plan/goal` abandons the first (only one active).

- [ ] **Step 9: Verify.** `go build ./... && go test ./internal/...` → PASS.

- [ ] **Step 10: Commit.** `git commit -am "feat(plan): weight-goal persistence, plan API, routes"`

---

## Task 4: Frontend API client + types (contract)

**Files:**
- Create: `client/src/api/plan.ts`
- Modify: `client/src/types/index.ts` (extend `User`; add `PlanPayload`, `WeightGoal`, `BodyMetrics`)

**Interfaces:**
- Consumes: Task 3 routes/JSON shape.
- Produces: `getPlan(): Promise<PlanPayload>`, `updateMetrics(m)`, `upsertGoal(g)`, `applyBudget()`, `abandonGoal()`; `PlanPayload` type used by Tasks 5–7.

- [ ] **Step 1:** Add types to `client/src/types/index.ts` matching the GET /plan shape (camelCase keys as the handler emits). Extend `User` with `heightCm?: number|null; birthYear?: number|null; sex?: 'male'|'female'|'other'|null; activityLevel?: string|null`.
- [ ] **Step 2:** Write `client/src/api/plan.ts` using the existing `api<T>()` helper from `./client` (mirror `api/weight.ts`), one function per endpoint. Mutations POST/PUT JSON bodies.
- [ ] **Step 3: Verify.** `cd client && npm run build` (tsc) → PASS.
- [ ] **Step 4: Commit.** `git commit -am "feat(plan): client API + types"`

---

## Task 5: Plan page (metrics, goal, budget apply) + route + nav

**Files:**
- Create: `client/src/pages/Plan/Plan.tsx`
- Modify: `client/src/router.tsx` (add `<Route path="/plan" …>` inside `ProtectedRoute`)
- Modify: `client/src/components/Layout/Header.tsx` (nav `<Link to="/plan">Plan</Link>` between Dashboard and Settings, using `navClass('/plan')`)

**Interfaces:**
- Consumes: Task 4 API/types; existing `Card`, `Button`, `Input` UI, `useToastStore`, `useAuthStore`.
- Produces: `/plan` route rendering the planner; consumed by Task 6 (chart slot).

- [ ] **Step 1:** `Plan.tsx` with a `useQuery(['plan'], getPlan)`. Render sections from spec §6: status header (weight, BMI chip, healthy range), collapsible **Your details** form (height/age or birth-year/sex select/activity select → `updateMetrics` → invalidate `['plan']`), **Goal setup** (target weight, pace toggle rate/date, input; show live `computed.budgetKcal`, `etaDate`, `warnings`), **Recommended budget** block with `Apply as my calorie goal` button (shows `currentCalorieGoal`) → `applyBudget` → toast + invalidate `['plan']` and `['weight']`, **Progress** (percent + `trend.status` badge), **Disclaimer**. Respect `weightUnit` for display/input.
- [ ] **Step 2:** Wire route + nav link.
- [ ] **Step 3: Verify (build + manual).** `npm run build`; then run the stack (Task 8 harness) and confirm the page loads, metrics save, goal saves, budget applies.
- [ ] **Step 4: Commit.** `git commit -am "feat(plan): planner page with metrics, goal, and apply-budget"`

---

## Task 6: Dependency-free SVG chart

**Files:**
- Create: `client/src/pages/Plan/PlanChart.tsx`
- Modify: `client/src/pages/Plan/Plan.tsx` (mount `<PlanChart …>`)

**Interfaces:**
- Consumes: `PlanPayload.series`, `computed.planCurve`, `goal.targetWeight`, `healthyRange`, `trend`.
- Produces: `<PlanChart data={…} />` reusable by Task 7 as a compact sparkline (prop `variant?: 'full'|'spark'`).

- [ ] **Step 1:** Build an inline `<svg viewBox>` line chart (no library): x = date/week, y = kg. Draw healthy-range band (rect), target line (dashed), actual series (points + smoothed path), adaptive plan curve (distinct stroke). **Theme-aware** via Tailwind `currentColor`/CSS vars (per `dataviz` skill: readable in light + dark); responsive (`width:100%`, `preserveAspectRatio`), wrap in `overflow-x:auto`. Accessible `<title>`/`aria-label`.
- [ ] **Step 2:** Add `variant='spark'` (minimal: actual line + target line only, no axes) for the Dashboard card.
- [ ] **Step 3: Verify.** `npm run build`; visually confirm in light + dark (running stack).
- [ ] **Step 4: Commit.** `git commit -am "feat(plan): dependency-free SVG progress chart"`

---

## Task 7: Dashboard summary card

**Files:**
- Create: `client/src/pages/Dashboard/PlanCard.tsx`
- Modify: `client/src/pages/Dashboard/Dashboard.tsx` (mount `<PlanCard/>` near `WeightRow`)

**Interfaces:**
- Consumes: `getPlan` (own `useQuery`, lazy), `PlanChart variant='spark'`.

- [ ] **Step 1:** `PlanCard` renders only when `goal` active: `current → target`, percent-to-goal bar, `trend.status` badge, spark chart, link to `/plan`. Returns `null` when no active goal (so it's invisible for users who haven't set one).
- [ ] **Step 2:** Mount in `Dashboard.tsx` (canEdit/own-view only, like `WeightRow`).
- [ ] **Step 3: Verify.** `npm run build`; confirm card appears once a goal exists and links through.
- [ ] **Step 4: Commit.** `git commit -am "feat(plan): dashboard weight-goal summary card"`

---

## Task 8: e2e + docs + full verification

**Files:**
- Create: `e2e/plan.spec.ts`
- Modify: `README.md` (add planner to feature list)

- [ ] **Step 1:** Playwright spec (copy setup from an existing `e2e/*.spec.ts`): register/login a user → visit `/plan` → fill metrics → set goal by rate → assert a recommended budget number appears → click Apply → go to `/dashboard` → assert calorie goal reflects it. Second case: goal by an aggressive date → assert a warning is shown.
- [ ] **Step 2:** Add "Weight-loss planner (goal weight → calorie budget, timeline, progress)" to the README feature list.
- [ ] **Step 3: Full verification (quality gate).** Run: `go build ./... && go test ./...`; `cd client && npm run build`; bring up `compose.dev.yml`; drive the full flow with real data (set 180 cm / age 40 / male / moderate, goal 80 kg by 0.75 kg/wk → budget ≈ 2631; Apply → dashboard goal updates; chart renders light+dark). Then `npx playwright test e2e/plan.spec.ts` (per `playwright.config.ts`). Capture output.
- [ ] **Step 4: Commit.** `git commit -am "test(plan): e2e coverage and README update"`

---

## Self-Review (done during authoring)

- **Spec coverage:** metrics storage → T1; math (BMR/TDEE/budget/ETA/BMI/adaptive/trend/guardrails) → T2; goal storage + API + apply-budget + one-active invariant → T3; client contract → T4; page + metrics + goal + apply + nav → T5; chart → T6; dashboard card → T7; safety disclaimer surfaced in T3 payload + rendered T5; graceful degradation (no metrics → trend-only) handled in T3 GET logic + T5 rendering; e2e + docs → T8. ✅ All spec §§3–9 mapped.
- **Placeholder scan:** none — math + migrations are full code; handlers/pages give concrete logic + exact copy-from files. ✅
- **Type consistency:** `RateKgPerWeek`, `AdaptivePlanCurve`, `TrendAnalysis`, `RecommendedBudget(...)→(int,bool)`, `PlanPayload` keys consistent across T2→T3→T4→T5–7. ✅
