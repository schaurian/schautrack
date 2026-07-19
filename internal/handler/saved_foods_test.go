package handler

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func sfIntPtr(v int) *int { return &v }

func sfStrPtr(v string) *string { return &v }

func eqIntPtr(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// TestBuildTrackedEntry pins the Track business logic that turns a saved food
// into a calorie_entries row: quantity clamping (1..99), emoji-prefixed name
// truncation at 120 bytes on a rune boundary, calorie-amount multiplication
// with MaxEntryCalories overflow rejection, and per-macro multiplication with
// nil pass-through and MaxEntryMacro overflow rejection.
func TestBuildTrackedEntry(t *testing.T) {
	// A name whose emoji-prefixed form exceeds 120 bytes so truncation kicks
	// in. Each "🍕" is 4 bytes; 40 of them = 160 bytes, plus the "🥑 " prefix
	// (4 + 1 bytes) = 165 bytes total.
	longName := strings.Repeat("🍕", 40)
	wantTruncated := truncateUTF8("🥑 "+longName, 120)

	tests := []struct {
		name  string
		food  string
		emoji *string
		// template macro values on the saved food
		amount, protein, carbs, fat, fiber, sugar *int
		qty                                       int

		wantOk     bool
		wantQty    int // clamped
		wantName   string
		wantAmount int
		wantProt   *int
		wantCarbs  *int
		wantFat    *int
		wantFiber  *int
		wantSugar  *int
	}{
		{
			name: "basic no emoji qty 1", food: "Pizza", emoji: nil,
			amount: sfIntPtr(650), qty: 1,
			wantOk: true, wantQty: 1, wantName: "Pizza", wantAmount: 650,
		},
		{
			name: "emoji prefixed", food: "Pizza", emoji: sfStrPtr("🍕"),
			amount: sfIntPtr(650), qty: 2,
			wantOk: true, wantQty: 2, wantName: "🍕 Pizza", wantAmount: 1300,
		},
		{
			name: "empty emoji string not prefixed", food: "Pizza", emoji: sfStrPtr(""),
			amount: sfIntPtr(650), qty: 1,
			wantOk: true, wantQty: 1, wantName: "Pizza", wantAmount: 650,
		},
		{
			name: "qty below 1 clamps to 1", food: "Apple", emoji: nil,
			amount: sfIntPtr(95), qty: 0,
			wantOk: true, wantQty: 1, wantName: "Apple", wantAmount: 95,
		},
		{
			name: "negative qty clamps to 1", food: "Apple", emoji: nil,
			amount: sfIntPtr(95), qty: -7,
			wantOk: true, wantQty: 1, wantName: "Apple", wantAmount: 95,
		},
		{
			name: "qty above 99 clamps to 99", food: "Mint", emoji: nil,
			amount: sfIntPtr(1), qty: 500,
			wantOk: true, wantQty: 99, wantName: "Mint", wantAmount: 99,
		},
		{
			name: "nil amount yields zero", food: "Water", emoji: nil,
			amount: nil, qty: 5,
			wantOk: true, wantQty: 5, wantName: "Water", wantAmount: 0,
		},
		{
			name: "amount overflows MaxEntryCalories", food: "Cake", emoji: nil,
			amount: sfIntPtr(5000), qty: 3,
			wantOk: false, wantQty: 3,
		},
		{
			name: "negative amount underflows -MaxEntryCalories", food: "Refund", emoji: nil,
			amount: sfIntPtr(-5000), qty: 3,
			wantOk: false, wantQty: 3,
		},
		{
			name: "amount exactly at MaxEntryCalories", food: "Feast", emoji: nil,
			amount: sfIntPtr(3333), qty: 3,
			wantOk: true, wantQty: 3, wantName: "Feast", wantAmount: MaxEntryCalories,
		},
		{
			name: "macros multiply with nil pass-through", food: "Chicken", emoji: nil,
			amount: sfIntPtr(200), protein: sfIntPtr(30), carbs: nil, fat: sfIntPtr(5),
			fiber: nil, sugar: sfIntPtr(0), qty: 3,
			wantOk: true, wantQty: 3, wantName: "Chicken", wantAmount: 600,
			wantProt: sfIntPtr(90), wantCarbs: nil, wantFat: sfIntPtr(15),
			wantFiber: nil, wantSugar: sfIntPtr(0),
		},
		{
			name: "macro overflows MaxEntryMacro rejects", food: "Protein", emoji: nil,
			amount: sfIntPtr(10), protein: sfIntPtr(500), qty: 3,
			wantOk: false, wantQty: 3,
		},
		{
			name: "emoji-prefixed name truncated to 120 bytes on rune boundary",
			food: longName, emoji: sfStrPtr("🥑"), amount: nil, qty: 1,
			wantOk: true, wantQty: 1, wantName: wantTruncated, wantAmount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotQty, ok := buildTrackedEntry(tt.food, tt.emoji, tt.amount,
				tt.protein, tt.carbs, tt.fat, tt.fiber, tt.sugar, tt.qty)
			if ok != tt.wantOk {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOk)
			}
			if gotQty != tt.wantQty {
				t.Errorf("clamped qty = %d, want %d", gotQty, tt.wantQty)
			}
			if !tt.wantOk {
				return // fields are zero-valued on rejection; nothing else to check
			}
			if got.name != tt.wantName {
				t.Errorf("name = %q, want %q", got.name, tt.wantName)
			}
			if got.amount != tt.wantAmount {
				t.Errorf("amount = %d, want %d", got.amount, tt.wantAmount)
			}
			if !eqIntPtr(got.protein, tt.wantProt) {
				t.Errorf("protein = %v, want %v", got.protein, tt.wantProt)
			}
			if !eqIntPtr(got.carbs, tt.wantCarbs) {
				t.Errorf("carbs = %v, want %v", got.carbs, tt.wantCarbs)
			}
			if !eqIntPtr(got.fat, tt.wantFat) {
				t.Errorf("fat = %v, want %v", got.fat, tt.wantFat)
			}
			if !eqIntPtr(got.fiber, tt.wantFiber) {
				t.Errorf("fiber = %v, want %v", got.fiber, tt.wantFiber)
			}
			if !eqIntPtr(got.sugar, tt.wantSugar) {
				t.Errorf("sugar = %v, want %v", got.sugar, tt.wantSugar)
			}
			// Invariants that must hold for every produced name: valid UTF-8
			// (Postgres rejects invalid byte sequences) and never over 120 bytes.
			if !utf8.ValidString(got.name) {
				t.Errorf("name %q is not valid UTF-8", got.name)
			}
			if len(got.name) > 120 {
				t.Errorf("name is %d bytes, exceeds 120", len(got.name))
			}
		})
	}
}

// TestParseSavedFoodPayload covers the Create/Update request validation:
// required name (create only), name trimming + truncation, emoji clearing,
// amount arithmetic parsing with range enforcement, and macro integer bounds.
func TestParseSavedFoodPayload(t *testing.T) {
	tests := []struct {
		name       string
		body       map[string]any
		forCreate  bool
		wantStatus int
		check      func(t *testing.T, in *savedFoodInput)
	}{
		{
			name: "create with valid name", body: map[string]any{"name": "Pizza"},
			forCreate: true, wantStatus: 0,
			check: func(t *testing.T, in *savedFoodInput) {
				if !in.hasName || in.name != "Pizza" {
					t.Errorf("name = %q hasName=%v", in.name, in.hasName)
				}
			},
		},
		{
			name: "create missing name rejected", body: map[string]any{},
			forCreate: true, wantStatus: 400,
		},
		{
			name: "create blank name rejected", body: map[string]any{"name": "   "},
			forCreate: true, wantStatus: 400,
		},
		{
			name: "update without name is allowed", body: map[string]any{"amount": "500"},
			forCreate: false, wantStatus: 0,
			check: func(t *testing.T, in *savedFoodInput) {
				if in.hasName {
					t.Errorf("hasName = true, want false")
				}
				if !in.hasAmount || in.amount == nil || *in.amount != 500 {
					t.Errorf("amount = %v hasAmount=%v", in.amount, in.hasAmount)
				}
			},
		},
		{
			name: "name is trimmed then truncated to MaxSavedFoodName",
			body: map[string]any{"name": "  " + strings.Repeat("a", 100) + "  "},
			forCreate: true, wantStatus: 0,
			check: func(t *testing.T, in *savedFoodInput) {
				if len(in.name) != MaxSavedFoodName {
					t.Errorf("name len = %d, want %d", len(in.name), MaxSavedFoodName)
				}
			},
		},
		{
			name: "emoji set", body: map[string]any{"name": "x", "emoji": "🍕"},
			forCreate: true, wantStatus: 0,
			check: func(t *testing.T, in *savedFoodInput) {
				if !in.hasEmoji || in.emoji == nil || *in.emoji != "🍕" {
					t.Errorf("emoji = %v hasEmoji=%v", in.emoji, in.hasEmoji)
				}
			},
		},
		{
			name: "empty emoji clears to nil", body: map[string]any{"name": "x", "emoji": ""},
			forCreate: true, wantStatus: 0,
			check: func(t *testing.T, in *savedFoodInput) {
				if !in.hasEmoji || in.emoji != nil {
					t.Errorf("emoji = %v hasEmoji=%v, want nil+present", in.emoji, in.hasEmoji)
				}
			},
		},
		{
			name: "amount arithmetic expression evaluated",
			body: map[string]any{"name": "x", "amount": "2*3"},
			forCreate: true, wantStatus: 0,
			check: func(t *testing.T, in *savedFoodInput) {
				if !in.hasAmount || in.amount == nil || *in.amount != 6 {
					t.Errorf("amount = %v, want 6", in.amount)
				}
			},
		},
		{
			name: "amount unparseable rejected",
			body: map[string]any{"name": "x", "amount": "abc"},
			forCreate: true, wantStatus: 400,
		},
		{
			name: "amount over MaxEntryCalories rejected",
			body: map[string]any{"name": "x", "amount": "99999"},
			forCreate: true, wantStatus: 400,
		},
		{
			name: "explicit nil amount leaves hasAmount false",
			body: map[string]any{"name": "x", "amount": nil},
			forCreate: true, wantStatus: 0,
			check: func(t *testing.T, in *savedFoodInput) {
				if in.hasAmount {
					t.Errorf("hasAmount = true, want false for nil amount")
				}
			},
		},
		{
			name: "valid macro parsed",
			body: map[string]any{"name": "x", "protein_g": float64(50)},
			forCreate: true, wantStatus: 0,
			check: func(t *testing.T, in *savedFoodInput) {
				if v, ok := in.macros["protein"]; !ok || v == nil || *v != 50 {
					t.Errorf("protein = %v ok=%v", v, ok)
				}
			},
		},
		{
			name: "macro over MaxEntryMacro rejected",
			body: map[string]any{"name": "x", "protein_g": float64(1500)},
			forCreate: true, wantStatus: 400,
		},
		{
			name: "negative macro rejected",
			body: map[string]any{"name": "x", "carbs_g": float64(-5)},
			forCreate: true, wantStatus: 400,
		},
		{
			name: "explicit nil macro recorded as nil",
			body: map[string]any{"name": "x", "fat_g": nil},
			forCreate: true, wantStatus: 0,
			check: func(t *testing.T, in *savedFoodInput) {
				v, ok := in.macros["fat"]
				if !ok || v != nil {
					t.Errorf("fat macro = %v present=%v, want present+nil", v, ok)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, status, msg := parseSavedFoodPayload(tt.body, tt.forCreate)
			if status != tt.wantStatus {
				t.Fatalf("status = %d (%q), want %d", status, msg, tt.wantStatus)
			}
			if tt.wantStatus != 0 {
				if in != nil {
					t.Errorf("input = %v, want nil on error", in)
				}
				if msg == "" {
					t.Errorf("error status with empty message")
				}
				return
			}
			if in == nil {
				t.Fatalf("input = nil on success")
			}
			if tt.check != nil {
				tt.check(t, in)
			}
		})
	}
}
