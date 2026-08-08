package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"schautrack/internal/middleware"
	"schautrack/internal/service"
)

// CreateEntry handles POST /entries
func (h *EntriesHandler) CreateEntry(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)
	userTz := getUserTimezone(r, user)
	mu := service.ParseMacroUser(user.MacrosEnabled, user.MacroGoals, user.DailyGoal, user.GoalThreshold)

	// An absent or null amount reads as the empty string, which ParseAmount
	// rejects — the same outcome the old fmt.Sprintf("%v", nil) => "<nil>"
	// coercion reached, without the sentinel.
	rawAmount := ""
	if v, _ := optionalString(body, "amount"); v != nil {
		rawAmount = *v
	}
	amount := classifyAmount(rawAmount, MaxEntryCalories)

	entryDate, _ := body["entry_date"].(string)
	entryDate = strings.TrimSpace(entryDate)
	if entryDate == "" {
		entryDate = service.FormatDateInTz(time.Now(), userTz)
	}
	if !isValidDate(entryDate) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid date")
		return
	}
	// Absent and null both mean "no name"; there is nothing to preserve on a
	// create, so the two collapse to a NULL entry_name.
	entryName, _ := optionalEntryName(body, "entry_name")

	// Parse weight (frontend may send as string or number)
	var weightVal float64
	hasWeight := false
	if wv, _ := optionalString(body, "weight"); wv != nil && *wv != "" {
		wr := service.ParseWeight(*wv)
		if wr.Ok {
			weightVal = wr.Value
			hasWeight = true
		}
	}

	bodyFat, ok := parseBodyFatUpdate(body)
	if !ok {
		ErrorJSON(w, http.StatusBadRequest, "Invalid body fat")
		return
	}

	// Parse macros
	macroValues := map[string]int{}
	for _, key := range service.MacroKeys {
		fieldName := key + "_g"
		v, _ := optionalString(body, fieldName)
		if v == nil || *v == "" {
			continue
		}
		n, err := strconv.Atoi(*v)
		if err != nil || n < 0 || n > MaxEntryMacro {
			ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Macro values must be between 0 and %d", MaxEntryMacro))
			return
		}
		macroValues[key] = n
	}
	hasMacroEntry := len(macroValues) > 0

	// Auto-calc calories
	if service.IsAutoCalcCalories(mu) && hasMacroEntry {
		p := macroValues["protein"]
		c := macroValues["carbs"]
		f := macroValues["fat"]
		if computed := service.ComputeCaloriesFromMacros(p, c, f); computed != nil && *computed > 0 {
			if !entryCaloriesInRange(*computed) {
				ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Calories computed from macros exceed the maximum of %d", MaxEntryCalories))
				return
			}
			// A computed amount replaces whatever the request sent, so an
			// unparseable `amount` field is no longer grounds for a 400.
			amount = amountDecision{Value: *computed, HasCalorieEntry: true}
		}
	}

	if amount.Reject {
		ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Calories must be between -%d and %d", MaxEntryCalories, MaxEntryCalories))
		return
	}

	if !amount.HasCalorieEntry && !hasMacroEntry && !hasWeight {
		ErrorJSON(w, http.StatusBadRequest, "Invalid entry data")
		return
	}

	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to save entry")
		return
	}
	defer tx.Rollback(r.Context())

	if amount.HasCalorieEntry || hasMacroEntry {
		entryAmount := 0
		if amount.HasCalorieEntry {
			entryAmount = amount.Value
		}
		// Build dynamic query
		cols := "user_id, entry_date, amount, entry_name"
		vals := "$1, $2, $3, $4"
		args := []any{user.ID, entryDate, entryAmount, entryName}
		idx := 5
		for _, key := range service.MacroKeys {
			if v, ok := macroValues[key]; ok {
				cols += ", " + key + "_g"
				vals += fmt.Sprintf(", $%d", idx)
				args = append(args, v)
				idx++
			}
		}
		_, err := tx.Exec(r.Context(), fmt.Sprintf("INSERT INTO calorie_entries (%s) VALUES (%s)", cols, vals), args...)
		if err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Failed to save entry")
			return
		}
	}

	if hasWeight {
		_, err := service.UpsertWeightEntry(r.Context(), tx, user.ID, entryDate, weightVal, bodyFat)
		if err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Failed to save weight")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to save entry")
		return
	}

	if amount.HasCalorieEntry || hasMacroEntry {
		h.Broker.BroadcastEntryChange(user.ID)
	}
	OkJSON(w)
}

// UpdateEntry handles POST /entries/:id/update
func (h *EntriesHandler) UpdateEntry(w http.ResponseWriter, r *http.Request) {
	entryID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid entry id")
		return
	}

	var body map[string]any
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)
	mu := service.ParseMacroUser(user.MacrosEnabled, user.MacroGoals, user.DailyGoal, user.GoalThreshold)
	autoCalc := service.IsAutoCalcCalories(mu)
	userTz := getUserTimezone(r, user)

	updates, values, badRequest := buildEntryUpdates(body, autoCalc)
	if badRequest != "" {
		ErrorJSON(w, http.StatusBadRequest, badRequest)
		return
	}

	if len(updates) == 0 {
		ErrorJSON(w, http.StatusBadRequest, "No updates provided")
		return
	}

	// buildEntryUpdates numbered its placeholders $1..$len(updates), so the id
	// and user_id predicates continue from there.
	idx := len(updates) + 1

	query := fmt.Sprintf(
		"UPDATE calorie_entries SET %s WHERE id = $%d AND user_id = $%d RETURNING id, entry_date, amount, entry_name, created_at, protein_g, carbs_g, fat_g, fiber_g, sugar_g",
		strings.Join(updates, ", "), idx, idx+1)
	values = append(values, entryID, user.ID)

	var id int
	var entryDate string
	var amount int
	var entryName *string
	var createdAt time.Time
	var proteinG, carbsG, fatG, fiberG, sugarG *int

	// Run the field update and the auto-calc amount update in one
	// transaction so a rejected computed amount can't leave the entry
	// half-updated (name/macros committed, amount stale).
	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to update entry")
		return
	}
	defer tx.Rollback(r.Context())

	err = tx.QueryRow(r.Context(), query, values...).Scan(
		&id, &entryDate, &amount, &entryName, &createdAt,
		&proteinG, &carbsG, &fatG, &fiberG, &sugarG)
	if err != nil {
		ErrorJSON(w, http.StatusNotFound, "Entry not found")
		return
	}

	// Auto-calc calories
	if autoCalc {
		p, c, f := intOrZero(proteinG), intOrZero(carbsG), intOrZero(fatG)
		if computed := service.ComputeCaloriesFromMacros(p, c, f); computed != nil {
			if !entryCaloriesInRange(*computed) {
				ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Calories computed from macros exceed the maximum of %d", MaxEntryCalories))
				return
			}
			if _, err := tx.Exec(r.Context(), "UPDATE calorie_entries SET amount = $1 WHERE id = $2 AND user_id = $3", *computed, entryID, user.ID); err != nil {
				ErrorJSON(w, http.StatusInternalServerError, "Failed to update entry")
				return
			}
			amount = *computed
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to update entry")
		return
	}

	enabledMacros := service.GetEnabledMacros(mu)
	macros := buildMacroMap(enabledMacros, proteinG, carbsG, fatG, fiberG, sugarG)

	payload := map[string]any{
		"id": id, "date": entryDate, "amount": amount,
		"time": service.FormatTimeInTz(createdAt, userTz),
		"name": entryName, "macros": macros,
	}

	h.Broker.BroadcastEntryChange(user.ID)
	JSON(w, http.StatusOK, map[string]any{"ok": true, "entry": payload})
}

// DeleteEntry handles POST /entries/:id/delete
func (h *EntriesHandler) DeleteEntry(w http.ResponseWriter, r *http.Request) {
	entryID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid entry id")
		return
	}
	user := middleware.GetCurrentUser(r)
	tag, err := h.Pool.Exec(r.Context(), "DELETE FROM calorie_entries WHERE id = $1 AND user_id = $2", entryID, user.ID)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to delete entry")
		return
	}
	if tag.RowsAffected() == 0 {
		ErrorJSON(w, http.StatusNotFound, "Entry not found")
		return
	}
	h.Broker.BroadcastEntryChange(user.ID)
	OkJSON(w)
}
