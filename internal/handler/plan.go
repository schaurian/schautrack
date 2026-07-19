package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/service"
	"schautrack/internal/sse"
)

type PlanHandler struct {
	Pool   *pgxpool.Pool
	Broker *sse.Broker
}

var validSexes = map[string]bool{"male": true, "female": true, "other": true}

var validActivityLevels = map[string]bool{
	"sedentary": true, "light": true, "moderate": true, "active": true, "very_active": true,
}

func validateHeightCm(h *float64) bool {
	return h == nil || (*h >= 50 && *h <= 300)
}

func validateBirthYear(y *int, currentYear int) bool {
	return y == nil || (*y >= 1900 && *y <= currentYear-10)
}

func validateSex(s *string) bool {
	return s == nil || validSexes[*s]
}

func validateActivityLevel(a *string) bool {
	return a == nil || validActivityLevels[*a]
}

func validateTargetWeight(w float64) bool {
	return w > 0
}

func validatePaceMode(m string) bool {
	return m == "rate" || m == "date"
}

func validateRateKgPerWeek(paceMode string, rate *float64) bool {
	if paceMode != "rate" {
		return true
	}
	return rate != nil && *rate > 0
}

// validateTargetDate requires a well-formed, strictly-future YYYY-MM-DD date
// when paceMode is "date"; it's a no-op for other pace modes. now is injected
// so the check is pure/testable.
func validateTargetDate(paceMode string, dateStr *string, now time.Time) bool {
	if paceMode != "date" {
		return true
	}
	if dateStr == nil || !dateRe.MatchString(*dateStr) {
		return false
	}
	return *dateStr > now.Format("2006-01-02")
}

// currentCalorieGoal reads the user's effective calorie target: macro_goals.calories,
// falling back to the legacy daily_goal column.
func currentCalorieGoal(user *model.User) *int {
	var macroGoals map[string]any
	json.Unmarshal(user.MacroGoals, &macroGoals)
	if v, ok := macroGoals["calories"]; ok {
		if n, ok := v.(float64); ok {
			i := int(n)
			return &i
		}
	}
	return user.DailyGoal
}

// gatherPlan pulls everything AssemblePlan needs straight from the DB for the
// current user and returns the computed payload plus the active goal (if any).
func (h *PlanHandler) gatherPlan(r *http.Request, user *model.User) (service.PlanResponse, *model.WeightGoal, error) {
	ctx := r.Context()

	lastWeight, err := service.GetLastWeightEntry(ctx, h.Pool, user.ID, "")
	if err != nil {
		return service.PlanResponse{}, nil, err
	}
	var currentWeight *float64
	if lastWeight != nil {
		w := lastWeight.Weight
		currentWeight = &w
	}

	tz := getUserTimezone(r, user)
	since := service.SubtractDaysUTC(service.FormatDateInTz(time.Now(), tz), 179)
	series, err := service.GetWeightSeries(ctx, h.Pool, user.ID, since)
	if err != nil {
		return service.PlanResponse{}, nil, err
	}

	goal, err := service.GetActiveGoal(ctx, h.Pool, user.ID)
	if err != nil {
		return service.PlanResponse{}, nil, err
	}

	resp := service.AssemblePlan(service.PlanInputs{
		CurrentWeight:  currentWeight,
		HeightCm:       user.HeightCm,
		BirthYear:      user.BirthYear,
		Sex:            user.Sex,
		ActivityLevel:  user.ActivityLevel,
		Goal:           goal,
		Series:         series,
		CurrentCalGoal: currentCalorieGoal(user),
		Now:            time.Now(),
	})
	return resp, goal, nil
}

// Get handles GET /plan
func (h *PlanHandler) Get(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)

	resp, goal, err := h.gatherPlan(r, user)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not load plan.")
		return
	}

	if resp.GoalReachedNow && goal != nil {
		if err := service.MarkGoalAchieved(r.Context(), h.Pool, goal.ID); err != nil {
			slog.Error("failed to mark goal achieved", "error", err)
		} else if resp.Goal != nil {
			resp.Goal.Status = "achieved"
		}
	}

	JSON(w, http.StatusOK, resp)
}

// UpdateMetrics handles PUT /plan/metrics
func (h *PlanHandler) UpdateMetrics(w http.ResponseWriter, r *http.Request) {
	var body struct {
		HeightCm      *float64 `json:"height_cm"`
		BirthYear     *int     `json:"birth_year"`
		Sex           *string  `json:"sex"`
		ActivityLevel *string  `json:"activity_level"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	currentYear := time.Now().Year()
	if !validateHeightCm(body.HeightCm) || !validateBirthYear(body.BirthYear, currentYear) ||
		!validateSex(body.Sex) || !validateActivityLevel(body.ActivityLevel) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid body metrics.")
		return
	}

	user := middleware.GetCurrentUser(r)
	if err := service.UpdateBodyMetrics(r.Context(), h.Pool, user.ID, body.HeightCm, body.BirthYear, body.Sex, body.ActivityLevel); err != nil {
		slog.Error("failed to update body metrics", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Could not save metrics.")
		return
	}
	OkJSON(w)
}

// UpsertGoal handles PUT /plan/goal
func (h *PlanHandler) UpsertGoal(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TargetWeight  float64  `json:"target_weight"`
		PaceMode      string   `json:"pace_mode"`
		RateKgPerWeek *float64 `json:"rate_kg_per_week"`
		TargetDate    *string  `json:"target_date"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	now := time.Now()
	if !validateTargetWeight(body.TargetWeight) || !validatePaceMode(body.PaceMode) ||
		!validateRateKgPerWeek(body.PaceMode, body.RateKgPerWeek) ||
		!validateTargetDate(body.PaceMode, body.TargetDate, now) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid goal.")
		return
	}

	user := middleware.GetCurrentUser(r)

	lastWeight, err := service.GetLastWeightEntry(r.Context(), h.Pool, user.ID, "")
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not load current weight.")
		return
	}
	if lastWeight == nil {
		ErrorJSON(w, http.StatusBadRequest, "Log a weight entry before setting a goal.")
		return
	}

	tz := getUserTimezone(r, user)
	startDate := service.FormatDateInTz(now, tz)

	goal := &model.WeightGoal{
		UserID:        user.ID,
		StartWeight:   lastWeight.Weight,
		StartDate:     startDate,
		TargetWeight:  body.TargetWeight,
		PaceMode:      body.PaceMode,
		RateKgPerWeek: body.RateKgPerWeek,
		TargetDate:    body.TargetDate,
		ActivityLevel: user.ActivityLevel,
	}

	saved, err := service.UpsertActiveGoal(r.Context(), h.Pool, goal)
	if err != nil {
		slog.Error("failed to upsert weight goal", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Could not save goal.")
		return
	}
	if h.Broker != nil {
		h.Broker.BroadcastEntryChange(user.ID)
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "goal": saved})
}

// ApplyBudget handles POST /plan/goal/apply-budget
func (h *PlanHandler) ApplyBudget(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)

	resp, _, err := h.gatherPlan(r, user)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not compute budget.")
		return
	}
	if resp.Computed == nil {
		ErrorJSON(w, http.StatusBadRequest, "No active goal or incomplete body metrics.")
		return
	}
	budget := resp.Computed.BudgetKcal

	// Mirrors internal/handler/settings.go's Macros update: read-modify-write
	// the macro_goals JSONB, only touching the calories key.
	var macroGoals map[string]any
	json.Unmarshal(user.MacroGoals, &macroGoals)
	if macroGoals == nil {
		macroGoals = map[string]any{}
	}
	macroGoals["calories"] = budget
	goalsJSON, err := json.Marshal(macroGoals)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not apply budget.")
		return
	}

	if _, err := h.Pool.Exec(r.Context(), "UPDATE users SET macro_goals = $1 WHERE id = $2", goalsJSON, user.ID); err != nil {
		slog.Error("failed to apply plan budget", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Could not apply budget.")
		return
	}
	if h.Broker != nil {
		h.Broker.BroadcastEntryChange(user.ID)
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "budget": budget})
}

// AbandonGoal handles POST /plan/goal/abandon
func (h *PlanHandler) AbandonGoal(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	if err := service.AbandonActiveGoal(r.Context(), h.Pool, user.ID); err != nil {
		slog.Error("failed to abandon weight goal", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Could not abandon goal.")
		return
	}
	if h.Broker != nil {
		h.Broker.BroadcastEntryChange(user.ID)
	}
	OkJSON(w)
}
