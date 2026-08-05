package service

import "testing"

func TestLeanAndFatMass(t *testing.T) {
	// 80 kg at 25% -> 60 kg lean, 20 kg fat. Split by hand, not by calling the
	// functions under test.
	if got := LeanBodyMass(80, 25); !almost(got, 60, 1e-9) {
		t.Errorf("LeanBodyMass(80, 25) = %v, want 60", got)
	}
	if got := FatMass(80, 25); !almost(got, 20, 1e-9) {
		t.Errorf("FatMass(80, 25) = %v, want 20", got)
	}
	// The two must always reconstitute the original weight.
	if got := LeanBodyMass(93.4, 31.7) + FatMass(93.4, 31.7); !almost(got, 93.4, 1e-9) {
		t.Errorf("lean + fat = %v, want 93.4", got)
	}

	for _, tc := range []struct {
		desc            string
		weight, bodyFat float64
	}{
		{"zero weight", 0, 25},
		{"negative weight", -80, 25},
		{"zero body fat", 80, 0},
		{"negative body fat", 80, -5},
		{"body fat at 100", 80, 100},
		{"body fat above 100", 80, 140},
	} {
		if got := LeanBodyMass(tc.weight, tc.bodyFat); got != 0 {
			t.Errorf("LeanBodyMass %s = %v, want 0", tc.desc, got)
		}
		if got := FatMass(tc.weight, tc.bodyFat); got != 0 {
			t.Errorf("FatMass %s = %v, want 0", tc.desc, got)
		}
	}
}

func TestBMRKatchMcArdle(t *testing.T) {
	// 370 + 21.6 * 62.3 = 370 + 1345.68 = 1715.68
	if got := BMRKatchMcArdle(62.3); !almost(got, 1715.68, 0.01) {
		t.Errorf("BMRKatchMcArdle(62.3) = %v, want 1715.68", got)
	}
	if got := BMRKatchMcArdle(0); got != 0 {
		t.Errorf("BMRKatchMcArdle(0) = %v, want 0", got)
	}
	if got := BMRKatchMcArdle(-10); got != 0 {
		t.Errorf("BMRKatchMcArdle(-10) = %v, want 0", got)
	}
}

func TestBodyFatCategory(t *testing.T) {
	tests := []struct {
		sex     Sex
		pct     float64
		want    string
		comment string
	}{
		// Male bands: essential <6, athletic <14, fitness <18, average <25.
		{SexMale, 4, "essential", ""},
		{SexMale, 5.9, "essential", "just under the athletic bound"},
		{SexMale, 6, "athletic", "bounds are inclusive lower edges"},
		{SexMale, 13.9, "athletic", ""},
		{SexMale, 14, "fitness", ""},
		{SexMale, 17.9, "fitness", ""},
		{SexMale, 18, "average", ""},
		{SexMale, 24.9, "average", ""},
		{SexMale, 25, "obese", ""},
		{SexMale, 40, "obese", ""},
		// Female bands sit ~8 points higher across the board.
		{SexFemale, 12, "essential", ""},
		{SexFemale, 14, "athletic", ""},
		{SexFemale, 21, "fitness", ""},
		{SexFemale, 25, "average", ""},
		{SexFemale, 32, "obese", ""},
		{SexFemale, 24, "fitness", "would be 'obese' on the male bands"},
		// "other" is the male/female midpoint.
		{SexOther, 9, "essential", ""},
		{SexOther, 10, "athletic", ""},
		{SexOther, 17.5, "fitness", ""},
		{SexOther, 21.5, "average", ""},
		{SexOther, 28.5, "obese", ""},
	}
	for _, tt := range tests {
		if got := BodyFatCategory(tt.sex, tt.pct); got != tt.want {
			t.Errorf("BodyFatCategory(%q, %v) = %q, want %q %s", tt.sex, tt.pct, got, tt.want, tt.comment)
		}
	}

	// An unknown sex has no bands to classify against — better to say nothing
	// than to guess, since the male and female bands differ by ~8 points.
	if got := BodyFatCategory(Sex("unknown"), 20); got != "" {
		t.Errorf("BodyFatCategory with unknown sex = %q, want \"\"", got)
	}
	if got := BodyFatCategory(SexMale, 0); got != "" {
		t.Errorf("BodyFatCategory(male, 0) = %q, want \"\"", got)
	}
	if got := BodyFatCategory(SexMale, 100); got != "" {
		t.Errorf("BodyFatCategory(male, 100) = %q, want \"\"", got)
	}
}

func TestKatchMcArdleModel(t *testing.T) {
	// 100 kg at 30% body fat -> 70 kg lean -> 370 + 21.6*70 = 1882 kcal.
	m := KatchMcArdleModel(100, 30)
	if got := m(100); !almost(got, 1882, 0.01) {
		t.Errorf("model at the anchor weight = %v, want 1882", got)
	}

	// 10 kg lost, 25% of it lean -> 67.5 kg lean -> 370 + 21.6*67.5 = 1828.
	if got := m(90); !almost(got, 1828, 0.01) {
		t.Errorf("model at 90kg = %v, want 1828", got)
	}

	// The whole point of the lean-mass model: BMR falls by 21.6*0.25 = 5.4
	// kcal per kg lost, against Mifflin's 10. A projection that decays at
	// Mifflin's rate would mean the body-fat reading changed nothing.
	slope := (m(100) - m(90)) / 10
	if !almost(slope, 5.4, 1e-9) {
		t.Errorf("BMR slope = %v kcal/kg, want 5.4", slope)
	}
	mifflin := MifflinModel(SexMale, 180, 40)
	mifflinSlope := (mifflin(100) - mifflin(90)) / 10
	if !almost(mifflinSlope, 10, 1e-9) {
		t.Errorf("Mifflin slope = %v kcal/kg, want 10", mifflinSlope)
	}
}

func TestAdaptivePlanCurveWithKatchMcArdleDeceleratesMoreSlowly(t *testing.T) {
	// Same start, target and budget under both models. Because Katch–McArdle
	// loses only 5.4 kcal/kg of maintenance instead of 10, the deficit stays
	// wider for longer and the target arrives in fewer weeks.
	const start, target, budget = 100.0, 85.0, 2000.0
	mifflin := AdaptivePlanCurve(start, target, budget, MifflinModel(SexMale, 180, 40), ActivityModerate, 200)
	katch := AdaptivePlanCurve(start, target, budget, KatchMcArdleModel(start, 30), ActivityModerate, 200)

	if len(mifflin) < 2 || len(katch) < 2 {
		t.Fatalf("expected both curves to have points, got %d and %d", len(mifflin), len(katch))
	}
	if last := katch[len(katch)-1].Weight; last > target+0.5 {
		t.Errorf("katch curve did not reach the target: ended at %v", last)
	}

	// Both still decelerate — neither model projects a straight line.
	d0 := katch[0].Weight - katch[1].Weight
	dN := katch[len(katch)-2].Weight - katch[len(katch)-1].Weight
	if d0 <= dN {
		t.Errorf("expected the katch curve to decelerate: first week %v, last week %v", d0, dN)
	}
}
