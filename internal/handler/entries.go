package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/sse"
)

const (
	MaxHistoryDays   = 180
	DefaultRangeDays = 14
	MaxEntryCalories = 9999
	MaxEntryMacro    = 999
)

var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// EntriesHandler holds deps for entry routes.
type EntriesHandler struct {
	Pool     *pgxpool.Pool
	Broker   *sse.Broker
	Cfg      *config.Config
	Settings *database.SettingsCache
}

func (h *EntriesHandler) isBarcodeEnabled(ctx context.Context) bool {
	result := h.Settings.GetEffectiveSetting(ctx, "enable_barcode", os.Getenv("ENABLE_BARCODE"))
	if result.Value == nil {
		return true // default enabled
	}
	return *result.Value != "false"
}

type dailyStat struct {
	Date          string `json:"date"`
	Total         int    `json:"total"`
	Status        string `json:"status"`
	OverThreshold bool   `json:"overThreshold"`
}

// Dashboard handles GET /api/dashboard
func (h *EntriesHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	userTz := getUserTimezone(r, user)
	todayStrTz := service.FormatDateInTz(time.Now(), userTz)

	requestedRange, _ := strconv.Atoi(r.URL.Query().Get("range"))
	requestedDays := DefaultRangeDays
	ignoreCustomRange := false
	if requestedRange >= 7 {
		requestedDays = min(max(requestedRange, 7), MaxHistoryDays)
		ignoreCustomRange = true
	}

	var startParam, endParam string
	if !ignoreCustomRange {
		startParam = r.URL.Query().Get("start")
		endParam = r.URL.Query().Get("end")
	}
	startDate, endDate := sanitizeDateRange(startParam, endParam, requestedDays, userTz)
	dayOptions := service.BuildDayOptionsBetween(startDate, endDate, MaxHistoryDays)
	if len(dayOptions) == 0 {
		dayOptions = []string{todayStrTz}
	}
	oldest := dayOptions[len(dayOptions)-1]
	newest := dayOptions[0]
	todayStr := service.FormatDateInTz(time.Now(), userTz)

	requestedDate := strings.TrimSpace(r.URL.Query().Get("day"))
	selectedDate := newest
	if service.ContainsString(dayOptions, requestedDate) {
		selectedDate = requestedDate
	} else if service.ContainsString(dayOptions, todayStr) {
		selectedDate = todayStr
	}

	mu := service.ParseMacroUser(user.MacrosEnabled, user.MacroGoals, user.DailyGoal, user.GoalThreshold)
	totalsByDate := getTotalsByDate(r, h.Pool, user.ID, oldest, newest)
	todayTotal := totalsByDate[todayStr]
	macroModes := service.GetMacroModes(mu)
	enabledMacros := service.GetEnabledMacros(mu)
	macroGoals := service.GetMacroGoals(mu)
	var macroTotalsByDate map[string]map[string]int
	if len(enabledMacros) > 0 {
		macroTotalsByDate, _ = service.GetMacroTotalsByDate(r.Context(), h.Pool, user.ID, oldest, newest)
	}
	todayMacroTotals := map[string]int{}
	if macroTotalsByDate != nil {
		if t, ok := macroTotalsByDate[todayStr]; ok {
			todayMacroTotals = t
		}
	}
	dailyGoal := service.GetCalorieGoal(mu)

	dailyStats := buildDailyStats(dayOptions, totalsByDate, dailyGoal, enabledMacros, macroGoals, macroModes, macroTotalsByDate, mu.GoalThreshold)

	caloriesEnabled := true
	if v, ok := mu.MacrosEnabled["calories"]; ok && v == false {
		caloriesEnabled = false
	}
	autoCalcCalories := service.IsAutoCalcCalories(mu)

	var calorieStatus service.MacroStatus
	if caloriesEnabled {
		calorieStatus = service.ComputeMacroStatus(todayTotal, dailyGoal, macroModes["calories"], mu.GoalThreshold)
	}

	goalStatus := "unset"
	var goalDelta *int
	if dailyGoal != nil {
		if todayTotal <= *dailyGoal {
			goalStatus = "under"
		} else {
			s := service.ComputeMacroStatus(todayTotal, dailyGoal, "limit", mu.GoalThreshold)
			if s.StatusClass == "macro-stat--danger" {
				goalStatus = "over_threshold"
			} else {
				goalStatus = "over"
			}
		}
		d := intAbs(*dailyGoal - todayTotal)
		goalDelta = &d
	}

	// Fetch entries for selected date
	entries := getEntriesForDate(r, h.Pool, user.ID, selectedDate, enabledMacros, userTz)

	// Macro statuses
	macroStatuses := map[string]service.MacroStatus{}
	for _, key := range enabledMacros {
		total := todayMacroTotals[key]
		goal, ok := macroGoals[key]
		var goalPtr *int
		if ok {
			goalPtr = &goal
		}
		macroStatuses[key] = service.ComputeMacroStatus(total, goalPtr, macroModes[key], mu.GoalThreshold)
	}

	// Links
	acceptedLinks, _ := service.GetAcceptedLinkUsers(r.Context(), h.Pool, user.ID)

	// Weight
	weightEntry, _ := service.GetWeightEntry(r.Context(), h.Pool, user.ID, selectedDate)
	lastWeightEntry, _ := service.GetLastWeightEntry(r.Context(), h.Pool, user.ID, selectedDate)
	var viewWeight any
	if weightEntry != nil {
		timeFormatted := service.FormatTimeInTz(weightEntry.UpdatedAt, userTz)
		viewWeight = map[string]any{
			"id": weightEntry.ID, "entry_date": weightEntry.Date, "weight": weightEntry.Weight,
			"created_at": weightEntry.CreatedAt, "updated_at": weightEntry.UpdatedAt,
			"timeFormatted": timeFormatted,
		}
	}

	// Shared views
	sharedViews := []any{
		map[string]any{
			"userId": user.ID, "email": user.Email, "label": "You", "isSelf": true,
			"dailyGoal": dailyGoal, "goalThreshold": mu.GoalThreshold,
			"dailyStats": dailyStats, "todayStr": todayStrTz,
		},
	}
	for _, link := range acceptedLinks {
		lmu := link.AsMacroUser()
		linkTodayStr := service.FormatDateInTz(time.Now(), link.Timezone)
		var linkDayOptions []string
		for _, d := range dayOptions {
			if d <= linkTodayStr {
				linkDayOptions = append(linkDayOptions, d)
			}
		}
		if len(linkDayOptions) == 0 {
			continue
		}
		linkOldest := linkDayOptions[len(linkDayOptions)-1]
		linkNewest := linkDayOptions[0]
		linkGoal := service.GetCalorieGoal(lmu)
		linkTotals := getTotalsByDate(r, h.Pool, link.UserID, linkOldest, linkNewest)
		linkEnabledMacros := service.GetEnabledMacros(lmu)
		linkMacroGoals := service.GetMacroGoals(lmu)
		linkMacroModes := service.GetMacroModes(lmu)
		var linkMacroTotals map[string]map[string]int
		if len(linkEnabledMacros) > 0 {
			linkMacroTotals, _ = service.GetMacroTotalsByDate(r.Context(), h.Pool, link.UserID, linkOldest, linkNewest)
		}
		stats := buildDailyStats(linkDayOptions, linkTotals, linkGoal, linkEnabledMacros, linkMacroGoals, linkMacroModes, linkMacroTotals, lmu.GoalThreshold)

		label := link.Email
		if link.Label != nil && strings.TrimSpace(*link.Label) != "" {
			label = *link.Label
		}
		sharedViews = append(sharedViews, map[string]any{
			"linkId": link.LinkID, "userId": link.UserID, "email": link.Email,
			"label": label, "isSelf": false,
			"dailyGoal": linkGoal, "goalThreshold": lmu.GoalThreshold,
			"dailyStats": stats, "todayStr": linkTodayStr,
		})
	}

	// AI status: show button if user has personal key OR global key is available
	hasAiEnabled := user.AIKey != nil && *user.AIKey != ""
	if !hasAiEnabled {
		globalKey := h.Settings.GetEffectiveSetting(r.Context(), "ai_key", h.Cfg.AIKey)
		hasAiEnabled = globalKey.Value != nil && *globalKey.Value != ""
	}

	tz := "UTC"
	if user.Timezone != nil {
		tz = *user.Timezone
	}

	var macrosEnabledAny, macroGoalsAny any
	json.Unmarshal(user.MacrosEnabled, &macrosEnabledAny)
	json.Unmarshal(user.MacroGoals, &macroGoalsAny)
	if macrosEnabledAny == nil {
		macrosEnabledAny = map[string]any{}
	}
	if macroGoalsAny == nil {
		macroGoalsAny = map[string]any{}
	}

	rangePreset := requestedDays
	if r.URL.Query().Get("start") != "" || r.URL.Query().Get("end") != "" {
		rangePreset = 0
	}

	JSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id": user.ID, "email": user.Email, "timezone": tz,
			"weightUnit": user.WeightUnit, "dailyGoal": user.DailyGoal,
			"totpEnabled": user.TOTPEnabled, "macrosEnabled": macrosEnabledAny,
			"macroGoals": macroGoalsAny, "goalThreshold": mu.GoalThreshold,
			"preferredAiProvider": nilStr(user.PreferredAIProvider),
			"hasAiKey": user.AIKey != nil && *user.AIKey != "",
			"aiModel": user.AIModel, "aiDailyLimit": user.AIDailyLimit,
			"todosEnabled": user.TodosEnabled,
		},
		"dailyGoal": dailyGoal, "todayTotal": todayTotal,
		"goalStatus": goalStatus, "goalDelta": goalDelta,
		"dailyStats": dailyStats, "dayOptions": dayOptions, "selectedDate": selectedDate,
		"recentEntries": entries, "sharedViews": sharedViews,
		"weightUnit": user.WeightUnit, "timeZone": userTz, "todayStr": todayStrTz,
		"range": map[string]any{"start": oldest, "end": newest, "days": len(dayOptions), "preset": nilInt(rangePreset)},
		"weightEntry": viewWeight, "lastWeightEntry": lastWeightEntry,
		"hasAiEnabled": hasAiEnabled, "aiUsage": nil, "aiProviderName": nil,
		"barcodeEnabled": h.isBarcodeEnabled(r.Context()),
		"caloriesEnabled": caloriesEnabled, "autoCalcCalories": autoCalcCalories,
		"enabledMacros": enabledMacros, "macroGoals": macroGoals,
		"todayMacroTotals": todayMacroTotals, "macroLabels": service.MacroLabels,
		"macroModes": macroModes, "macroStatuses": macroStatuses, "calorieStatus": calorieStatus,
	})
}

// DayEntries handles GET /entries/day
func (h *EntriesHandler) DayEntries(w http.ResponseWriter, r *http.Request) {
	dateStr := strings.TrimSpace(r.URL.Query().Get("date"))
	if !dateRe.MatchString(dateStr) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid date")
		return
	}

	user := middleware.GetCurrentUser(r)
	targetUser := middleware.GetTargetUser(r)
	if targetUser == nil {
		targetUser = user
	}
	targetUserID := targetUser.ID

	// Use viewer's tz for self, target's tz for linked users
	displayTz := getUserTimezone(r, user)
	if targetUserID != user.ID {
		displayTz = targetUser.GetTimezone()
		if displayTz == "" {
			displayTz = "UTC"
		}
	}

	enabledMacros := service.GetEnabledMacros(service.ParseMacroUser(targetUser.MacrosEnabled, targetUser.MacroGoals, targetUser.DailyGoal, targetUser.GoalThreshold))
	entries := getEntriesForDate(r, h.Pool, targetUserID, dateStr, enabledMacros, displayTz)

	JSON(w, http.StatusOK, map[string]any{"ok": true, "date": dateStr, "entries": entries})
}

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
		result := service.ParseAmount(fmt.Sprintf("%v", v), MaxEntryCalories)
		if !result.Ok || result.Value == 0 {
			ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Calories must be between -%d and %d", MaxEntryCalories, MaxEntryCalories))
			return
		}
		updates = append(updates, fmt.Sprintf("amount = $%d", idx))
		values = append(values, result.Value)
		idx++
	}

	for _, key := range service.MacroKeys {
		fieldName := key + "_g"
		if v, ok := body[fieldName]; ok {
			vStr := strings.TrimSpace(fmt.Sprintf("%v", v))
			if vStr == "" || vStr == "<nil>" {
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

// Overview handles GET /overview
func (h *EntriesHandler) Overview(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	targetUser := middleware.GetTargetUser(r)
	if targetUser == nil {
		targetUser = user
	}
	targetUserID := targetUser.ID
	mu := service.ParseMacroUser(targetUser.MacrosEnabled, targetUser.MacroGoals, targetUser.DailyGoal, targetUser.GoalThreshold)
	viewerTz := getUserTimezone(r, user)
	targetTz := targetUser.GetTimezone()
	if targetTz == "" {
		targetTz = viewerTz
	}

	requestedRange, _ := strconv.Atoi(r.URL.Query().Get("range"))
	rangeDays := DefaultRangeDays
	if requestedRange >= 7 {
		rangeDays = min(max(requestedRange, 7), MaxHistoryDays)
	}

	startDate, endDate := sanitizeDateRange(r.URL.Query().Get("start"), r.URL.Query().Get("end"), rangeDays, viewerTz)
	dayOptions := service.BuildDayOptionsBetween(startDate, endDate, MaxHistoryDays)
	if len(dayOptions) == 0 {
		dayOptions = []string{service.FormatDateInTz(time.Now(), targetTz)}
	}
	oldest := dayOptions[len(dayOptions)-1]
	newest := dayOptions[0]
	todayStrTz := service.FormatDateInTz(time.Now(), targetTz)

	dailyGoal := service.GetCalorieGoal(mu)
	totalsByDate := getTotalsByDate(r, h.Pool, targetUserID, oldest, newest)
	todayTotal := totalsByDate[todayStrTz]
	threshold := mu.GoalThreshold
	enabledMacros := service.GetEnabledMacros(mu)
	macroGoals := service.GetMacroGoals(mu)
	macroModes := service.GetMacroModes(mu)
	var macroTotalsByDate map[string]map[string]int
	if len(enabledMacros) > 0 {
		macroTotalsByDate, _ = service.GetMacroTotalsByDate(r.Context(), h.Pool, targetUserID, oldest, newest)
	}

	dailyStats := buildDailyStats(dayOptions, totalsByDate, dailyGoal, enabledMacros, macroGoals, macroModes, macroTotalsByDate, threshold)

	goalStatus := "unset"
	var goalDelta *int
	if dailyGoal != nil {
		if todayTotal <= *dailyGoal {
			goalStatus = "under"
		} else {
			s := service.ComputeMacroStatus(todayTotal, dailyGoal, "limit", threshold)
			if s.StatusClass == "macro-stat--danger" {
				goalStatus = "over_threshold"
			} else {
				goalStatus = "over"
			}
		}
		d := intAbs(*dailyGoal - todayTotal)
		goalDelta = &d
	}

	JSON(w, http.StatusOK, map[string]any{
		"ok": true, "userId": targetUserID,
		"dailyGoal": dailyGoal, "goalThreshold": threshold,
		"todayTotal": todayTotal, "todayStr": todayStrTz,
		"goalStatus": goalStatus, "goalDelta": goalDelta,
		"dailyStats": dailyStats, "dayOptions": dayOptions,
		"range": map[string]any{"start": oldest, "end": newest},
	})
}

// --- helpers ---

func getUserTimezone(r *http.Request, user interface{ GetTimezone() string }) string {
	if tz := user.GetTimezone(); tz != "" {
		return tz
	}
	if tz := middleware.GetClientTimezone(r); tz != "" {
		return tz
	}
	return "UTC"
}

func sanitizeDateRange(startStr, endStr string, fallbackDays int, userTz string) (string, string) {
	todayStr := service.FormatDateInTz(time.Now(), userTz)
	endDate := todayStr
	if endStr != "" && dateRe.MatchString(strings.TrimSpace(endStr)) {
		e := strings.TrimSpace(endStr)
		if e <= todayStr {
			endDate = e
		}
	}

	fallbackStart := service.SubtractDaysUTC(endDate, fallbackDays-1)
	startDate := fallbackStart
	if startStr != "" && dateRe.MatchString(strings.TrimSpace(startStr)) {
		startDate = strings.TrimSpace(startStr)
	}
	if startDate > endDate {
		startDate = endDate
	}
	maxLookback := service.SubtractDaysUTC(endDate, MaxHistoryDays-1)
	if startDate < maxLookback {
		startDate = maxLookback
	}
	return startDate, endDate
}

func getTotalsByDate(r *http.Request, pool *pgxpool.Pool, userID int, oldest, newest string) map[string]int {
	rows, err := pool.Query(r.Context(),
		"SELECT entry_date, SUM(amount) AS total FROM calorie_entries WHERE user_id = $1 AND entry_date BETWEEN $2 AND $3 GROUP BY entry_date",
		userID, oldest, newest)
	if err != nil {
		return map[string]int{}
	}
	defer rows.Close()
	result := map[string]int{}
	for rows.Next() {
		var date string
		var total int
		rows.Scan(&date, &total)
		result[date] = total
	}
	return result
}

func buildDailyStats(dayOptions []string, totalsByDate map[string]int, dailyGoal *int, enabledMacros []string, macroGoals map[string]int, macroModes map[string]string, macroTotalsByDate map[string]map[string]int, threshold int) []dailyStat {
	stats := make([]dailyStat, 0, len(dayOptions))
	for _, dateStr := range dayOptions {
		total := totalsByDate[dateStr]
		_, hasEntries := totalsByDate[dateStr]
		var statuses []string

		if dailyGoal != nil {
			if !hasEntries {
				statuses = append(statuses, "zero")
			} else {
				calMode := "limit"
				if m, ok := macroModes["calories"]; ok {
					calMode = m
				}
				cs := service.ComputeMacroStatus(total, dailyGoal, calMode, threshold)
				statuses = append(statuses, service.ComputeDotStatus(cs.StatusClass))
			}
		}

		if hasEntries && macroTotalsByDate != nil && len(enabledMacros) > 0 {
			dayMacros := macroTotalsByDate[dateStr]
			for _, key := range enabledMacros {
				goal, ok := macroGoals[key]
				if !ok || goal == 0 {
					continue
				}
				macroTotal := 0
				if dayMacros != nil {
					macroTotal = dayMacros[key]
				}
				mode := macroModes[key]
				if mode == "" {
					mode = "limit"
				}
				ms := service.ComputeMacroStatus(macroTotal, &goal, mode, threshold)
				statuses = append(statuses, service.ComputeDotStatus(ms.StatusClass))
			}
		}

		status := "none"
		if len(statuses) > 0 {
			status = service.WorstDotStatus(statuses)
		}

		stats = append(stats, dailyStat{
			Date: dateStr, Total: total, Status: status,
			OverThreshold: status == "over_threshold",
		})
	}
	return stats
}

func getEntriesForDate(r *http.Request, pool *pgxpool.Pool, userID int, dateStr string, enabledMacros []string, tz string) []map[string]any {
	rows, err := pool.Query(r.Context(),
		"SELECT id, entry_date, amount, entry_name, created_at, protein_g, carbs_g, fat_g, fiber_g, sugar_g FROM calorie_entries WHERE user_id = $1 AND entry_date = $2 ORDER BY created_at DESC",
		userID, dateStr)
	if err != nil {
		slog.Error("failed to fetch entries", "error", err)
		return []map[string]any{}
	}
	defer rows.Close()

	var result []map[string]any
	for rows.Next() {
		var id int
		var entryDate string
		var amount int
		var entryName *string
		var createdAt time.Time
		var proteinG, carbsG, fatG, fiberG, sugarG *int
		if err := rows.Scan(&id, &entryDate, &amount, &entryName, &createdAt, &proteinG, &carbsG, &fatG, &fiberG, &sugarG); err != nil {
			continue
		}
		macros := buildMacroMap(enabledMacros, proteinG, carbsG, fatG, fiberG, sugarG)
		entry := map[string]any{
			"id": id, "date": entryDate, "amount": amount,
			"time": service.FormatTimeInTz(createdAt, tz),
			"name": entryName, "macros": macros,
		}
		result = append(result, entry)
	}
	if result == nil {
		result = []map[string]any{}
	}
	return result
}

func buildMacroMap(enabledMacros []string, proteinG, carbsG, fatG, fiberG, sugarG *int) map[string]any {
	if len(enabledMacros) == 0 {
		return nil
	}
	macros := map[string]any{}
	macroVals := map[string]*int{
		"protein": proteinG, "carbs": carbsG, "fat": fatG, "fiber": fiberG, "sugar": sugarG,
	}
	for _, key := range enabledMacros {
		macros[key] = macroVals[key]
	}
	if len(macros) == 0 {
		return nil
	}
	return macros
}

func nilString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nilInt(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

func intAbs(x int) int {
	return int(math.Abs(float64(x)))
}

func intOrZero(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
