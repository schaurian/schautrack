package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"schautrack/internal/middleware"
	"schautrack/internal/service"
)

// Export handles GET /settings/export
func (h *EntriesHandler) Export(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	mu := service.ParseMacroUser(user.MacrosEnabled, user.MacroGoals, user.DailyGoal, user.GoalThreshold)

	entries, err := h.Pool.Query(r.Context(),
		"SELECT entry_date, amount, entry_name, created_at, protein_g, carbs_g, fat_g, fiber_g, sugar_g FROM calorie_entries WHERE user_id = $1 ORDER BY entry_date DESC, id DESC LIMIT 100000",
		user.ID)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Export failed")
		return
	}
	defer entries.Close()

	weights, err := h.Pool.Query(r.Context(),
		"SELECT entry_date, weight FROM weight_entries WHERE user_id = $1 ORDER BY entry_date DESC, id DESC LIMIT 100000",
		user.ID)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Export failed")
		return
	}
	defer weights.Close()

	filename := fmt.Sprintf("schautrack-export-%s.json", time.Now().Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))

	tz := "UTC"
	if user.Timezone != nil {
		tz = *user.Timezone
	}

	var macrosEnabled, macroGoalsRaw any
	if err := json.Unmarshal(user.MacrosEnabled, &macrosEnabled); err != nil {
		slog.Error("failed to unmarshal macros_enabled in export", "error", err)
	}
	if err := json.Unmarshal(user.MacroGoals, &macroGoalsRaw); err != nil {
		slog.Error("failed to unmarshal macro_goals in export", "error", err)
	}
	if macrosEnabled == nil {
		macrosEnabled = map[string]any{}
	}
	if macroGoalsRaw == nil {
		macroGoalsRaw = map[string]any{}
	}

	userExport := map[string]any{
		"email": user.Email, "daily_goal": service.GetCalorieGoal(mu),
		"macros_enabled": macrosEnabled, "macro_goals": macroGoalsRaw,
		"weight_unit": user.WeightUnit, "timezone": tz,
	}

	fmt.Fprint(w, "{\n")
	fmt.Fprintf(w, `"exported_at":%q,`+"\n", time.Now().UTC().Format(time.RFC3339))
	userJSON, _ := json.Marshal(userExport)
	fmt.Fprintf(w, `"user":%s,`+"\n", userJSON)

	// Weights
	fmt.Fprint(w, `"weights":[`)
	first := true
	for weights.Next() {
		var date string
		var weight float64
		if err := weights.Scan(&date, &weight); err != nil {
			slog.Error("failed to scan weight row in export", "error", err)
			continue
		}
		if !first {
			fmt.Fprint(w, ",")
		}
		wj, _ := json.Marshal(map[string]any{"date": date, "weight": weight})
		w.Write(wj)
		first = false
	}
	fmt.Fprint(w, "],\n")

	// Entries
	fmt.Fprint(w, `"entries":[`)
	first = true
	for entries.Next() {
		var date string
		var amount int
		var name *string
		var createdAt *time.Time
		var proteinG, carbsG, fatG, fiberG, sugarG *int
		if err := entries.Scan(&date, &amount, &name, &createdAt, &proteinG, &carbsG, &fatG, &fiberG, &sugarG); err != nil {
			slog.Error("failed to scan entry row in export", "error", err)
			continue
		}
		if !first {
			fmt.Fprint(w, ",")
		}
		entry := map[string]any{"date": date, "amount": amount, "name": name}
		if createdAt != nil {
			entry["created_at"] = createdAt.UTC().Format(time.RFC3339)
		}
		if proteinG != nil {
			entry["protein_g"] = *proteinG
		}
		if carbsG != nil {
			entry["carbs_g"] = *carbsG
		}
		if fatG != nil {
			entry["fat_g"] = *fatG
		}
		if fiberG != nil {
			entry["fiber_g"] = *fiberG
		}
		if sugarG != nil {
			entry["sugar_g"] = *sugarG
		}
		ej, _ := json.Marshal(entry)
		w.Write(ej)
		first = false
	}
	fmt.Fprint(w, "]\n}")
}

// Import handles POST /settings/import
func (h *EntriesHandler) Import(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form (max 10MB)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "No file uploaded.")
		return
	}
	file, _, err := r.FormFile("import_file")
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "No file uploaded.")
		return
	}
	defer file.Close()

	raw, err := io.ReadAll(io.LimitReader(file, 10<<20))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Could not read file.")
		return
	}

	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid JSON file.")
		return
	}

	user := middleware.GetCurrentUser(r)
	mu := service.ParseMacroUser(user.MacrosEnabled, user.MacroGoals, user.DailyGoal, user.GoalThreshold)

	// Extract calorie goal from various formats
	var goalCandidate *float64
	if userObj, ok := parsed["user"].(map[string]any); ok {
		if mg, ok := userObj["macro_goals"].(map[string]any); ok {
			if v, ok := mg["calories"].(float64); ok {
				goalCandidate = &v
			}
		}
	}
	if goalCandidate == nil {
		if v, ok := parsed["daily_goal"].(float64); ok {
			goalCandidate = &v
		}
	}
	if goalCandidate == nil {
		if userObj, ok := parsed["user"].(map[string]any); ok {
			if v, ok := userObj["daily_goal"].(float64); ok {
				goalCandidate = &v
			}
		}
	}

	// Parse entries
	type importEntry struct {
		date      string
		amount    int
		name      *string
		createdAt *time.Time
		macros    map[string]*int
	}
	var toInsert []importEntry
	if entries, ok := parsed["entries"].([]any); ok {
		for _, e := range entries {
			if len(toInsert) >= 10000 {
				break
			}
			entry, ok := e.(map[string]any)
			if !ok {
				continue
			}
			dateStr := ""
			if v, ok := entry["date"].(string); ok {
				dateStr = v
			} else if v, ok := entry["entry_date"].(string); ok {
				dateStr = v
			}
			if !dateRe.MatchString(dateStr) {
				continue
			}
			amountResult := service.ParseAmount(fmt.Sprintf("%v", entry["amount"]), MaxEntryCalories)
			if !amountResult.Ok || amountResult.Value == 0 {
				continue
			}
			var name *string
			if n, ok := entry["name"].(string); ok && n != "" {
				s := n
				if len(s) > 120 {
					s = s[:120]
				}
				name = &s
			} else if n, ok := entry["entry_name"].(string); ok && n != "" {
				s := n
				if len(s) > 120 {
					s = s[:120]
				}
				name = &s
			}
			var createdAt *time.Time
			if v, ok := entry["created_at"].(string); ok && v != "" {
				if t, err := time.Parse(time.RFC3339, v); err == nil {
					createdAt = &t
				}
			}
			macros := map[string]*int{}
			for _, key := range service.MacroKeys {
				field := key + "_g"
				if v, ok := entry[field]; ok {
					vStr := fmt.Sprintf("%v", v)
					if n, err := strconv.Atoi(vStr); err == nil && n >= 0 && n <= MaxEntryMacro {
						macros[key] = &n
					}
				}
			}
			toInsert = append(toInsert, importEntry{date: dateStr, amount: amountResult.Value, name: name, createdAt: createdAt, macros: macros})
		}
	}

	// Parse weight entries
	type importWeight struct {
		date   string
		weight float64
	}
	var weightToInsert []importWeight
	if weights, ok := parsed["weights"].([]any); ok {
		for _, w := range weights {
			if len(weightToInsert) >= 10000 {
				break
			}
			wEntry, ok := w.(map[string]any)
			if !ok {
				continue
			}
			dateStr := ""
			if v, ok := wEntry["date"].(string); ok {
				dateStr = v
			} else if v, ok := wEntry["entry_date"].(string); ok {
				dateStr = v
			}
			if !dateRe.MatchString(dateStr) {
				continue
			}
			wr := service.ParseWeight(fmt.Sprintf("%v", wEntry["weight"]))
			if !wr.Ok {
				continue
			}
			weightToInsert = append(weightToInsert, importWeight{date: dateStr, weight: wr.Value})
		}
	}

	// Check user settings
	hasUserSettings := false
	if userObj, ok := parsed["user"].(map[string]any); ok {
		if userObj["macros_enabled"] != nil || userObj["macro_goals"] != nil || goalCandidate != nil || userObj["weight_unit"] != nil || userObj["timezone"] != nil {
			hasUserSettings = true
		}
	}

	if len(toInsert) == 0 && len(weightToInsert) == 0 && !hasUserSettings {
		ErrorJSON(w, http.StatusBadRequest, "No valid entries found in import file.")
		return
	}

	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
		return
	}
	defer tx.Rollback(r.Context())

	if len(toInsert) > 0 {
		if _, err := tx.Exec(r.Context(), "DELETE FROM calorie_entries WHERE user_id = $1", user.ID); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
			return
		}
	}
	if len(weightToInsert) > 0 {
		if _, err := tx.Exec(r.Context(), "DELETE FROM weight_entries WHERE user_id = $1", user.ID); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
			return
		}
	}

	// Import user settings
	if userObj, ok := parsed["user"].(map[string]any); ok {
		importedMacrosEnabled, _ := userObj["macros_enabled"].(map[string]any)
		importedMacroGoals, _ := userObj["macro_goals"].(map[string]any)
		if importedMacrosEnabled != nil || importedMacroGoals != nil || goalCandidate != nil {
			meJSON, _ := json.Marshal(importedMacrosEnabled)
			mgJSON, _ := json.Marshal(importedMacroGoals)
			if _, err := tx.Exec(r.Context(), "UPDATE users SET macros_enabled = $1, macro_goals = $2 WHERE id = $3", meJSON, mgJSON, user.ID); err != nil {
				ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
				return
			}
		}
		if wu, ok := userObj["weight_unit"].(string); ok && (wu == "kg" || wu == "lb") {
			if _, err := tx.Exec(r.Context(), "UPDATE users SET weight_unit = $1 WHERE id = $2", wu, user.ID); err != nil {
				ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
				return
			}
		}
		if tz, ok := userObj["timezone"].(string); ok && len(tz) <= 50 {
			if _, err := tx.Exec(r.Context(), "UPDATE users SET timezone = $1, timezone_manual = TRUE WHERE id = $2", tz, user.ID); err != nil {
				ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
				return
			}
		}
	}

	// Insert entries
	for _, entry := range toInsert {
		cols := "user_id, entry_date, amount, entry_name"
		vals := "$1, $2, $3, $4"
		args := []any{user.ID, entry.date, entry.amount, entry.name}
		idx := 5
		if entry.createdAt != nil {
			cols += ", created_at"
			vals += fmt.Sprintf(", $%d", idx)
			args = append(args, *entry.createdAt)
			idx++
		}
		for _, key := range service.MacroKeys {
			if v, ok := entry.macros[key]; ok {
				cols += ", " + key + "_g"
				vals += fmt.Sprintf(", $%d", idx)
				args = append(args, v)
				idx++
			}
		}
		if _, err := tx.Exec(r.Context(), fmt.Sprintf("INSERT INTO calorie_entries (%s) VALUES (%s)", cols, vals), args...); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
			return
		}
	}

	for _, we := range weightToInsert {
		if _, err := service.UpsertWeightEntry(r.Context(), tx, user.ID, we.date, we.weight); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Import failed.")
			return
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Import failed — the file may contain invalid data.")
		return
	}

	var parts []string
	if len(toInsert) > 0 {
		parts = append(parts, fmt.Sprintf("%d entries", len(toInsert)))
	}
	if len(weightToInsert) > 0 {
		parts = append(parts, fmt.Sprintf("%d weight records", len(weightToInsert)))
	}
	if hasUserSettings {
		parts = append(parts, "user settings")
	}

	_ = mu // used for consistency
	JSON(w, http.StatusOK, map[string]any{"ok": true, "message": fmt.Sprintf("Imported %s.", strings.Join(parts, " and "))})
}
