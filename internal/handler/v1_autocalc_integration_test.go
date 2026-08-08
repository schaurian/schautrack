package handler

import (
	"fmt"
	"net/http"
	"testing"

	"schautrack/internal/service"
)

// Auto-calculated calories, the body-size ceiling, and the collection gaps that
// other open issues own.
//
// Auto-calc is the most intricate branch in v1_entries.go: it overrides a
// supplied calorie value, it rejects a macro combination whose computed total
// would break the amount CHECK, and the recompute shares a transaction with the
// field update precisely so a rejected total cannot leave macros committed
// against a stale calorie value. None of that was executed by a test.

// enableAutoCalc turns on the macro set that makes IsAutoCalcCalories true.
func (e *v1Env) enableAutoCalc() {
	e.t.Helper()

	if _, err := e.Pool.Exec(e.Ctx,
		`UPDATE users SET macros_enabled = '{"protein":true,"carbs":true,"fat":true,"auto_calc_calories":true}'::jsonb
		 WHERE id = $1`, e.UserID); err != nil {
		e.t.Fatalf("enabling auto-calc: %v", err)
	}
}

// TestV1AutoCalcDerivesCaloriesFromMacros: with auto-calc on, macros are
// authoritative and a supplied calorie value is recomputed rather than trusted
// — so an API-created entry is indistinguishable from a UI-created one.
func TestV1AutoCalcDerivesCaloriesFromMacros(t *testing.T) {
	e := newV1Env(t)
	e.enableAutoCalc()
	token := e.token(service.ScopeEntriesWrite)

	// 10*4 + 20*4 + 5*9 = 165, not the 5000 the caller asked for.
	rec := e.post("/api/v1/entries", token, `{"calories":5000,"protein_g":10,"carbs_g":20,"fat_g":5}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	var entry v1Entry
	decodeJSON(t, rec, &entry)
	if entry.Calories != 165 {
		t.Errorf("calories = %d, want the computed 165", entry.Calories)
	}
}

// TestV1AutoCalcRejectsAnImpossibleTotal: 999g of each macro computes to 16983,
// far past the amount CHECK. It must be a 422, not a constraint violation.
func TestV1AutoCalcRejectsAnImpossibleTotal(t *testing.T) {
	e := newV1Env(t)
	e.enableAutoCalc()
	token := e.token(service.ScopeEntriesWrite)

	rec := e.post("/api/v1/entries", token,
		fmt.Sprintf(`{"protein_g":%d,"carbs_g":%d,"fat_g":%d}`, MaxEntryMacro, MaxEntryMacro, MaxEntryMacro))

	p := requireProblem(t, rec, http.StatusUnprocessableEntity)
	if len(p.InvalidParams) == 0 || p.InvalidParams[0].Name != "calories" {
		t.Errorf("invalid_params = %+v, want it to name calories", p.InvalidParams)
	}
	var n int
	if err := e.Pool.QueryRow(e.Ctx,
		`SELECT COUNT(*)::int FROM calorie_entries WHERE user_id = $1`, e.UserID).Scan(&n); err != nil {
		t.Fatalf("counting entries: %v", err)
	}
	if n != 0 {
		t.Errorf("%d entries were written despite the 422", n)
	}
}

// TestV1AutoCalcMakesCaloriesReadOnly covers the PATCH branch: setting calories
// directly on an auto-calc account is refused rather than silently overwritten
// on the next macro edit.
func TestV1AutoCalcMakesCaloriesReadOnly(t *testing.T) {
	e := newV1Env(t)
	e.enableAutoCalc()
	token := e.token(service.ScopeEntriesWrite)

	entry := e.createEntry(token, `{"protein_g":10}`)

	rec := e.patch(fmt.Sprintf("/api/v1/entries/%d", entry.ID), token, `{"calories":500}`)
	p := requireProblem(t, rec, http.StatusUnprocessableEntity)
	if len(p.InvalidParams) == 0 || p.InvalidParams[0].Name != "calories" {
		t.Errorf("invalid_params = %+v, want it to name calories", p.InvalidParams)
	}
}

// TestV1AutoCalcRollsBackARejectedRecompute is the transaction assertion that
// UpdateEntryV1's comment promises. The macro UPDATE lands first and the
// recompute rejects afterwards; without the shared transaction the macros would
// be committed against a stale calorie value.
func TestV1AutoCalcRollsBackARejectedRecompute(t *testing.T) {
	e := newV1Env(t)
	e.enableAutoCalc()
	token := e.token(service.ScopeEntriesWrite)

	entry := e.createEntry(token, `{"protein_g":10}`) // 40 kcal

	rec := e.patch(fmt.Sprintf("/api/v1/entries/%d", entry.ID), token,
		fmt.Sprintf(`{"protein_g":%d,"carbs_g":%d,"fat_g":%d}`, MaxEntryMacro, MaxEntryMacro, MaxEntryMacro))
	requireProblem(t, rec, http.StatusUnprocessableEntity)

	var protein, carbs, fat *int
	var amount int
	if err := e.Pool.QueryRow(e.Ctx,
		`SELECT protein_g, carbs_g, fat_g, amount FROM calorie_entries WHERE id = $1`, entry.ID,
	).Scan(&protein, &carbs, &fat, &amount); err != nil {
		t.Fatalf("reading the entry back: %v", err)
	}
	if protein == nil || *protein != 10 {
		t.Errorf("protein_g = %v, want the original 10 — the rejected PATCH was not rolled back", protein)
	}
	if carbs != nil || fat != nil {
		t.Errorf("carbs_g = %v, fat_g = %v; the rejected PATCH committed macros", carbs, fat)
	}
	if amount != 40 {
		t.Errorf("amount = %d, want the original 40", amount)
	}
}

// TestV1BodyLimitIsEnforced: v1 caps a body at 1 MB, tighter than the global
// 15 MB, because nothing here takes a payload that size.
func TestV1BodyLimitIsEnforced(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeEntriesWrite)

	oversized := fmt.Sprintf(`{"calories":100,"name":%q}`, repeat("x", maxV1Body+1024))

	rec := e.post("/api/v1/entries", token, oversized)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body: %s)", rec.Code, truncateForLog(rec.Body.String()))
	}
	requireProblemShape(t, rec)

	// With an Idempotency-Key the body is read by the wrapper instead, which
	// must still refuse it as a client error rather than buffering it or 500ing.
	withKey := e.do(call{Method: http.MethodPost, Path: "/api/v1/entries", Token: token,
		Body: oversized, Headers: idempotent("too-big")})
	if withKey.Code < 400 || withKey.Code >= 500 {
		t.Fatalf("with an Idempotency-Key: status = %d, want a 4xx (body: %s)",
			withKey.Code, truncateForLog(withKey.Body.String()))
	}
	requireProblemShape(t, withKey)
}

// TestV1SavedFoodsCollectionDoesNotPaginate documents the behaviour #298 owns:
// GET /saved-foods honours `limit` but never reports that it truncated, so a
// sync client cannot tell a short page from a complete one.
//
// TODO(#298): when has_more/next_cursor are added (or the limit is dropped),
// turn this into the same pagination walk TestV1EntriesKeysetPagination... does.
func TestV1SavedFoodsCollectionDoesNotPaginate(t *testing.T) {
	e := newV1Env(t)
	token := e.token(service.ScopeFoodsWrite)

	for i := 0; i < 3; i++ {
		rec := e.post("/api/v1/saved-foods", token, fmt.Sprintf(`{"name":"Food %d","calories":%d}`, i, 100+i))
		if rec.Code != http.StatusCreated {
			t.Fatalf("seeding food %d: status = %d (body: %s)", i, rec.Code, rec.Body.String())
		}
	}

	rec := e.get("/api/v1/saved-foods?limit=2", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	requireSchema(t, rec, "SavedFoodList")

	var page v1List[v1SavedFood]
	decodeJSON(t, rec, &page)
	if len(page.Data) != 2 {
		t.Fatalf("got %d foods, want the requested 2", len(page.Data))
	}
	if page.HasMore != nil || page.NextCursor != nil {
		t.Fatalf("has_more/next_cursor are now populated (%v/%v) — #298 is fixed, so replace this "+
			"test with a real pagination walk", page.HasMore, page.NextCursor)
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n*len(s))
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

// truncateForLog keeps a failure message readable when the body is a megabyte.
func truncateForLog(s string) string {
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
