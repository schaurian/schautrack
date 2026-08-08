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

// --- #341: the "<nil>" sentinel in parseSavedFoodPayload -------------------
//
// parseSavedFoodPayload decoded request bodies into map[string]any and coerced
// every value with fmt.Sprintf("%v", …) before inspecting it, which renders a
// JSON null as the four-character string "<nil>". The emoji, amount and macro
// paths then compared against that sentinel to recover the null they had just
// destroyed; the name path did not compare at all.
//
// So POST /api/saved-foods with {"name": null} produced the name "<nil>",
// which — being a non-empty string — passed the "Name is required" check and
// created a saved food literally called <nil>. Same bug as #303 on the entries
// handler, and the reason it shipped is that parseSavedFoodPayload is pure but
// this matrix was never table-tested.
//
// Everything now reads through optionalString (entries_helpers.go), which
// separates absent / null / present before any coercion happens.

// sfBody decodes a JSON literal the way ReadJSON does, so these tests exercise
// the same value types the handler really sees (numbers as float64, an explicit
// null as a present key holding a nil interface). The older tests in this file
// build map[string]any by hand, which cannot express "key absent" versus
// "key present holding null" as unambiguously.
func sfBody(t *testing.T, raw string) map[string]any {
	t.Helper()
	return decodeBody(t, raw)
}

// TestParseSavedFoodPayloadName is the #341 regression proper. saved_foods.name
// is NOT NULL, so there is no "clear the name" state: an explicit null joins ""
// and whitespace as a 400, rather than becoming the string <nil>.
func TestParseSavedFoodPayloadName(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		forCreate bool
		wantOK    bool
		wantName  string
	}{
		{"absent on create is rejected", `{}`, true, false, ""},
		{"absent on update leaves the column alone", `{"amount":"500"}`, false, true, ""},
		// The bug. This used to return a saved food named "<nil>".
		{"null on create is rejected", `{"name":null}`, true, false, ""},
		{"null on update is rejected", `{"name":null}`, false, false, ""},
		{"empty string is rejected", `{"name":""}`, true, false, ""},
		{"whitespace is rejected", `{"name":"   "}`, true, false, ""},
		{"tabs and newlines are rejected", `{"name":"\t\n "}`, true, false, ""},
		{"a normal string is kept", `{"name":"Porridge"}`, true, true, "Porridge"},
		{"a padded string is trimmed", `{"name":"  Porridge  "}`, true, true, "Porridge"},
		// The bug's mirror image: a user may legitimately call a food <nil>,
		// and must get those four characters stored rather than a rejection.
		{"the literal <nil> is a real name", `{"name":"<nil>"}`, true, true, "<nil>"},
		{"a number becomes its text", `{"name":42}`, true, true, "42"},
		{"a zero becomes its text", `{"name":0}`, true, true, "0"},
		{"true becomes its text", `{"name":true}`, true, true, "true"},
		{"false becomes its text", `{"name":false}`, true, true, "false"},
		{"an object becomes its text", `{"name":{"a":1}}`, true, true, "map[a:1]"},
		{"an empty object becomes its text", `{"name":{}}`, true, true, "map[]"},
		{"an array becomes its text", `{"name":[1,2]}`, true, true, "[1 2]"},
		{"an empty array becomes its text", `{"name":[]}`, true, true, "[]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, status, msg := parseSavedFoodPayload(sfBody(t, tt.body), tt.forCreate)
			if !tt.wantOK {
				if status == 0 {
					t.Fatalf("accepted %s with name %q, want 400", tt.body, in.name)
				}
				if msg != "Name is required" {
					t.Errorf("message = %q, want %q", msg, "Name is required")
				}
				return
			}
			if status != 0 {
				t.Fatalf("rejected %s: %d %q", tt.body, status, msg)
			}
			if in.hasName != (tt.wantName != "") {
				t.Fatalf("hasName = %v for %s", in.hasName, tt.body)
			}
			if in.name != tt.wantName {
				t.Errorf("name = %q, want %q", in.name, tt.wantName)
			}
		})
	}
}

// TestParseSavedFoodPayloadNameIsCapped keeps the UTF-8-safe truncation the
// refactor moved from inside the coercion to after it.
func TestParseSavedFoodPayloadNameIsCapped(t *testing.T) {
	// 78 ASCII bytes + a 4-byte avocado = 82 bytes, so an 80-byte cap lands
	// two bytes inside the emoji and must walk back off it.
	utf8Boundary := strings.Repeat("a", 78) + "🥑"
	for _, tc := range []struct{ in, want string }{
		{strings.Repeat("b", 130), strings.Repeat("b", MaxSavedFoodName)},
		{utf8Boundary, strings.Repeat("a", 78)},
	} {
		in, status, msg := parseSavedFoodPayload(map[string]any{"name": tc.in}, true)
		if status != 0 {
			t.Fatalf("rejected a long name: %d %q", status, msg)
		}
		if in.name != tc.want {
			t.Errorf("name = %q (%d bytes), want %q (%d bytes)", in.name, len(in.name), tc.want, len(tc.want))
		}
		if len(in.name) > MaxSavedFoodName {
			t.Errorf("name is %d bytes, over the %d-byte cap", len(in.name), MaxSavedFoodName)
		}
		if !utf8.ValidString(in.name) {
			t.Errorf("name %q is not valid UTF-8; Postgres would reject it (22021)", in.name)
		}
	}
}

// TestParseSavedFoodPayloadEmoji pins the emoji column, which is nullable and
// therefore really does have a clear state. Only the literal "<nil>" changes
// behaviour: it used to clear the column and is now stored.
func TestParseSavedFoodPayloadEmoji(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantPresent bool
		wantNil     bool
		wantValue   string
	}{
		{"key absent leaves the column alone", `{"name":"x"}`, false, true, ""},
		{"null clears it", `{"name":"x","emoji":null}`, true, true, ""},
		{"empty string clears it", `{"name":"x","emoji":""}`, true, true, ""},
		{"whitespace clears it", `{"name":"x","emoji":"   "}`, true, true, ""},
		{"an emoji is stored", `{"name":"x","emoji":"🍕"}`, true, false, "🍕"},
		{"a normal string is stored", `{"name":"x","emoji":"pz"}`, true, false, "pz"},
		{"a padded value is trimmed", `{"name":"x","emoji":"  🍕  "}`, true, false, "🍕"},
		// Was silently cleared by the sentinel. Nonsense as an emoji either
		// way, but the point is that the four characters are no longer magic.
		{"the literal <nil> is stored verbatim", `{"name":"x","emoji":"<nil>"}`, true, false, "<nil>"},
		{"a number becomes its text", `{"name":"x","emoji":42}`, true, false, "42"},
		{"true becomes its text", `{"name":"x","emoji":true}`, true, false, "true"},
		{"an object becomes its text", `{"name":"x","emoji":{"a":1}}`, true, false, "map[a:1]"},
		{"an array becomes its text", `{"name":"x","emoji":[1,2]}`, true, false, "[1 2]"},
		{"an empty array becomes its text", `{"name":"x","emoji":[]}`, true, false, "[]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, status, msg := parseSavedFoodPayload(sfBody(t, tt.body), true)
			if status != 0 {
				t.Fatalf("rejected %s: %d %q", tt.body, status, msg)
			}
			if in.hasEmoji != tt.wantPresent {
				t.Fatalf("hasEmoji = %v, want %v", in.hasEmoji, tt.wantPresent)
			}
			if (in.emoji == nil) != tt.wantNil {
				t.Fatalf("emoji nil = %v, want %v (got %v)", in.emoji == nil, tt.wantNil, in.emoji)
			}
			if in.emoji != nil && *in.emoji != tt.wantValue {
				t.Errorf("emoji = %q, want %q", *in.emoji, tt.wantValue)
			}
			if in.emoji != nil && len(*in.emoji) > MaxSavedFoodEmoji {
				t.Errorf("emoji is %d bytes, over the %d-byte cap", len(*in.emoji), MaxSavedFoodEmoji)
			}
		})
	}
}

// TestParseSavedFoodPayloadAmount pins the amount column. Note the asymmetry
// preserved from before the refactor: an explicit null leaves hasAmount false
// (Update omits the column entirely), while an empty string clears it. Only the
// literal "<nil>" changes: it used to clear, and is now a 400 — the same call
// #338 made for the entry amount.
func TestParseSavedFoodPayloadAmount(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantSet   bool // hasAmount
		wantNil   bool
		wantValue int
		wantMsg   bool
	}{
		{"key absent leaves the column alone", `{"name":"x"}`, false, true, 0, false},
		{"null leaves hasAmount false", `{"name":"x","amount":null}`, false, true, 0, false},
		{"empty string clears it", `{"name":"x","amount":""}`, true, true, 0, false},
		{"whitespace clears it", `{"name":"x","amount":"   "}`, true, true, 0, false},
		{"a numeric string sets it", `{"name":"x","amount":"500"}`, true, false, 500, false},
		{"a JSON number sets it", `{"name":"x","amount":500}`, true, false, 500, false},
		{"an expression is evaluated", `{"name":"x","amount":"2*3"}`, true, false, 6, false},
		{"literal <nil> is rejected, not silently cleared", `{"name":"x","amount":"<nil>"}`, false, false, 0, true},
		{"a word is rejected", `{"name":"x","amount":"abc"}`, false, false, 0, true},
		{"true is rejected", `{"name":"x","amount":true}`, false, false, 0, true},
		{"an object is rejected", `{"name":"x","amount":{"a":1}}`, false, false, 0, true},
		{"an array is rejected", `{"name":"x","amount":[1,2]}`, false, false, 0, true},
		{"over the cap is rejected", `{"name":"x","amount":"99999"}`, false, false, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, status, msg := parseSavedFoodPayload(sfBody(t, tt.body), true)
			if (status != 0) != tt.wantMsg {
				t.Fatalf("status = %d (%q), wantMsg = %v", status, msg, tt.wantMsg)
			}
			if tt.wantMsg {
				return
			}
			if in.hasAmount != tt.wantSet {
				t.Fatalf("hasAmount = %v, want %v", in.hasAmount, tt.wantSet)
			}
			if (in.amount == nil) != tt.wantNil {
				t.Fatalf("amount nil = %v, want %v (got %v)", in.amount == nil, tt.wantNil, in.amount)
			}
			if in.amount != nil && *in.amount != tt.wantValue {
				t.Errorf("amount = %d, want %d", *in.amount, tt.wantValue)
			}
		})
	}
}

// TestParseSavedFoodPayloadMacros pins the macro columns. They are nullable, so
// null and "" both clear — but unlike the entries handler an explicit "0" here
// is a real zero, not a clear. Only the literal "<nil>" changes behaviour.
func TestParseSavedFoodPayloadMacros(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantPresent bool
		wantNil     bool
		wantValue   int
		wantMsg     bool
	}{
		{"key absent leaves the column alone", `{"name":"x"}`, false, true, 0, false},
		{"null clears it", `{"name":"x","protein_g":null}`, true, true, 0, false},
		{"empty string clears it", `{"name":"x","protein_g":""}`, true, true, 0, false},
		{"whitespace clears it", `{"name":"x","protein_g":"   "}`, true, true, 0, false},
		{"a numeric string sets it", `{"name":"x","protein_g":"50"}`, true, false, 50, false},
		{"a JSON number sets it", `{"name":"x","protein_g":50}`, true, false, 50, false},
		// Unlike buildEntryUpdates, where "0" means clear. Pinned so the two
		// surfaces are not "harmonised" by accident.
		{"zero is a real zero here, not a clear", `{"name":"x","protein_g":0}`, true, false, 0, false},
		{"literal <nil> is rejected, not silently cleared", `{"name":"x","protein_g":"<nil>"}`, false, false, 0, true},
		{"a word is rejected", `{"name":"x","protein_g":"abc"}`, false, false, 0, true},
		{"true is rejected", `{"name":"x","protein_g":true}`, false, false, 0, true},
		{"an object is rejected", `{"name":"x","protein_g":{"a":1}}`, false, false, 0, true},
		{"an array is rejected", `{"name":"x","protein_g":[1,2]}`, false, false, 0, true},
		{"a fraction is rejected", `{"name":"x","protein_g":30.5}`, false, false, 0, true},
		{"a negative value is rejected", `{"name":"x","protein_g":-5}`, false, false, 0, true},
		{"over the cap is rejected", `{"name":"x","protein_g":1500}`, false, false, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, status, msg := parseSavedFoodPayload(sfBody(t, tt.body), true)
			if (status != 0) != tt.wantMsg {
				t.Fatalf("status = %d (%q), wantMsg = %v", status, msg, tt.wantMsg)
			}
			if tt.wantMsg {
				return
			}
			v, present := in.macros["protein"]
			if present != tt.wantPresent {
				t.Fatalf("protein present = %v, want %v", present, tt.wantPresent)
			}
			if !present {
				return
			}
			if (v == nil) != tt.wantNil {
				t.Fatalf("protein nil = %v, want %v (got %v)", v == nil, tt.wantNil, v)
			}
			if v != nil && *v != tt.wantValue {
				t.Errorf("protein = %d, want %d", *v, tt.wantValue)
			}
		})
	}
}
