package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/service"
	"schautrack/internal/sse"
)

// EntriesHandler holds deps for entry routes.
type EntriesHandler struct {
	Pool     *pgxpool.Pool
	Broker   *sse.Broker
	Cfg      *config.Config
	Settings *database.SettingsCache
}

func (h *EntriesHandler) getAIProviderName(r *http.Request, user *model.User) *string {
	// Priority: env var > admin settings > user preference
	globalProvider := h.Settings.GetEffectiveSetting(r.Context(), "ai_provider", os.Getenv("AI_PROVIDER"))
	var provider string
	if globalProvider.Value != nil && *globalProvider.Value != "" {
		provider = *globalProvider.Value
	} else if user.PreferredAIProvider != "" {
		provider = user.PreferredAIProvider
	}
	if provider == "" {
		return nil
	}
	names := map[string]string{"openai": "OpenAI", "claude": "Anthropic", "ollama": "Ollama"}
	name := names[provider]
	if name == "" {
		name = provider
	}
	return &name
}

func (h *EntriesHandler) isBarcodeEnabled(ctx context.Context) bool {
	result := h.Settings.GetEffectiveSetting(ctx, "enable_barcode", os.Getenv("ENABLE_BARCODE"))
	if result.Value == nil {
		return true // default enabled
	}
	return *result.Value != "false"
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
	type linkResult struct {
		index int
		view  map[string]any
	}
	linkResults := make([]linkResult, len(acceptedLinks))
	var wg sync.WaitGroup
	for i, link := range acceptedLinks {
		wg.Add(1)
		go func(i int, link service.LinkUser) {
			defer wg.Done()
			lmu := link.AsMacroUser()
			linkTodayStr := service.FormatDateInTz(time.Now(), link.Timezone)
			var linkDayOptions []string
			for _, d := range dayOptions {
				if d <= linkTodayStr {
					linkDayOptions = append(linkDayOptions, d)
				}
			}
			if len(linkDayOptions) == 0 {
				return
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
			linkResults[i] = linkResult{index: i, view: map[string]any{
				"linkId": link.LinkID, "userId": link.UserID, "email": link.Email,
				"label": label, "isSelf": false,
				"dailyGoal": linkGoal, "goalThreshold": lmu.GoalThreshold,
				"dailyStats": stats, "todayStr": linkTodayStr,
			}}
		}(i, link)
	}
	wg.Wait()
	for _, res := range linkResults {
		if res.view != nil {
			sharedViews = append(sharedViews, res.view)
		}
	}

	// AI status: show button if user has personal key OR global key is available
	hasAiEnabled := user.AIKey != nil && *user.AIKey != ""
	usingGlobalKey := false
	if !hasAiEnabled {
		globalKey := h.Settings.GetEffectiveSetting(r.Context(), "ai_key", h.Cfg.AIKey)
		hasAiEnabled = globalKey.Value != nil && *globalKey.Value != ""
		if hasAiEnabled {
			usingGlobalKey = true
		}
	}

	// Compute AI usage for display
	var aiUsage any
	if hasAiEnabled {
		usedToday, _ := service.GetAIUsageToday(r.Context(), h.Pool, user.ID)
		var dailyLimit int
		if usingGlobalKey {
			dailyLimitSetting := h.Settings.GetEffectiveSetting(r.Context(), "ai_daily_limit", os.Getenv("AI_DAILY_LIMIT"))
			if dailyLimitSetting.Value != nil {
				dailyLimit, _ = strconv.Atoi(*dailyLimitSetting.Value)
			}
		} else if user.AIDailyLimit != nil {
			dailyLimit = *user.AIDailyLimit
		}
		remaining := dailyLimit - usedToday
		if dailyLimit == 0 || remaining < 0 {
			remaining = 0
		}
		aiUsage = map[string]any{
			"used": usedToday, "limit": dailyLimit, "remaining": remaining,
		}
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
		"hasAiEnabled": hasAiEnabled, "aiUsage": aiUsage, "aiProviderName": h.getAIProviderName(r, user),
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
