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
