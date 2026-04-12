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

	rawAmount := fmt.Sprintf("%v", body["amount"])
	amountResult := service.ParseAmount(rawAmount, MaxEntryCalories)
	hasCalorieEntry := amountResult.Ok && amountResult.Value != 0

	entryDate, _ := body["entry_date"].(string)
	if entryDate == "" {
		entryDate = service.FormatDateInTz(time.Now(), userTz)
	}
	entryName := ""
	if v, ok := body["entry_name"].(string); ok {
		entryName = strings.TrimSpace(v)
		if len(entryName) > 120 {
			entryName = entryName[:120]
		}
	}

	// Parse weight (frontend may send as string or number)
	var weightVal float64
	hasWeight := false
	if wv, exists := body["weight"]; exists && wv != nil {
		weightStr := fmt.Sprintf("%v", wv)
		if weightStr != "" && weightStr != "<nil>" {
			wr := service.ParseWeight(weightStr)
			if wr.Ok {
				weightVal = wr.Value
				hasWeight = true
			}
		}
	}

	// Parse macros
	macroValues := map[string]int{}
	for _, key := range service.MacroKeys {
		fieldName := key + "_g"
		if v, exists := body[fieldName]; exists {
			vStr := fmt.Sprintf("%v", v)
			vStr = strings.TrimSpace(vStr)
			if vStr == "" || vStr == "<nil>" {
				continue
			}
			n, err := strconv.Atoi(vStr)
			if err != nil || n < 0 || n > MaxEntryMacro {
				ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Macro values must be between 0 and %d", MaxEntryMacro))
				return
			}
			macroValues[key] = n
		}
	}
	hasMacroEntry := len(macroValues) > 0

	// Auto-calc calories
	if service.IsAutoCalcCalories(mu) && hasMacroEntry {
		p := macroValues["protein"]
		c := macroValues["carbs"]
		f := macroValues["fat"]
		if computed := service.ComputeCaloriesFromMacros(p, c, f); computed != nil && *computed > 0 {
			amountResult.Value = *computed
			amountResult.Ok = true
			hasCalorieEntry = true
		}
	}

	if rawAmount != "" && rawAmount != "<nil>" && !amountResult.Ok {
		ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Calories must be between -%d and %d", MaxEntryCalories, MaxEntryCalories))
		return
	}

	if !hasCalorieEntry && !hasMacroEntry && !hasWeight {
		ErrorJSON(w, http.StatusBadRequest, "Invalid entry data")
		return
	}

	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to save entry")
		return
	}
	defer tx.Rollback(r.Context())

	if hasCalorieEntry || hasMacroEntry {
		entryAmount := 0
		if hasCalorieEntry {
			entryAmount = amountResult.Value
		}
		// Build dynamic query
		cols := "user_id, entry_date, amount, entry_name"
		vals := "$1, $2, $3, $4"
		args := []any{user.ID, entryDate, entryAmount, nilString(entryName)}
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
		_, err := service.UpsertWeightEntry(r.Context(), tx, user.ID, entryDate, weightVal)
		if err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Failed to save weight")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to save entry")
		return
	}

	if hasCalorieEntry || hasMacroEntry {
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

	var updates []string
	var values []any
	idx := 1

	if v, ok := body["name"]; ok {
		name := strings.TrimSpace(fmt.Sprintf("%v", v))
		if len(name) > 120 {
			name = name[:120]
		}
		updates = append(updates, fmt.Sprintf("entry_name = $%d", idx))
		values = append(values, nilString(name))
		idx++
	}

	if v, ok := body["amount"]; ok && !autoCalc {
		vStr := strings.TrimSpace(fmt.Sprintf("%v", v))
		if vStr == "" || vStr == "<nil>" || vStr == "0" {
			updates = append(updates, fmt.Sprintf("amount = $%d", idx))
			values = append(values, 0)
			idx++
		} else {
			result := service.ParseAmount(vStr, MaxEntryCalories)
			if !result.Ok {
				ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Calories must be between -%d and %d", MaxEntryCalories, MaxEntryCalories))
				return
			}
			updates = append(updates, fmt.Sprintf("amount = $%d", idx))
			values = append(values, result.Value)
			idx++
		}
	}

	for _, key := range service.MacroKeys {
		fieldName := key + "_g"
		if v, ok := body[fieldName]; ok {
			vStr := strings.TrimSpace(fmt.Sprintf("%v", v))
			if vStr == "" || vStr == "<nil>" || vStr == "0" {
				updates = append(updates, fmt.Sprintf("%s = $%d", fieldName, idx))
				values = append(values, nil)
				idx++
			} else {
				n, err := strconv.Atoi(vStr)
				if err != nil || n < 0 || n > MaxEntryMacro {
					ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Macro values must be between 0 and %d", MaxEntryMacro))
					return
				}
				updates = append(updates, fmt.Sprintf("%s = $%d", fieldName, idx))
				values = append(values, n)
				idx++
			}
		}
	}

	if len(updates) == 0 {
		ErrorJSON(w, http.StatusBadRequest, "No updates provided")
		return
	}

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

	err = h.Pool.QueryRow(r.Context(), query, values...).Scan(
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
			if _, err := h.Pool.Exec(r.Context(), "UPDATE calorie_entries SET amount = $1 WHERE id = $2 AND user_id = $3", *computed, entryID, user.ID); err != nil {
				ErrorJSON(w, http.StatusInternalServerError, "Failed to update entry")
				return
			}
			amount = *computed
		}
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
	if _, err := h.Pool.Exec(r.Context(), "DELETE FROM calorie_entries WHERE id = $1 AND user_id = $2", entryID, user.ID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to delete entry")
		return
	}
	h.Broker.BroadcastEntryChange(user.ID)
	OkJSON(w)
}
