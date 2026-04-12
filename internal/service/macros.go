package service

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
)

var MacroKeys = []string{"protein", "carbs", "fat", "fiber", "sugar"}

type MacroLabel struct {
	Short string `json:"short"`
	Label string `json:"label"`
}

var MacroLabels = map[string]MacroLabel{
	"protein": {Short: "P", Label: "Protein"},
	"carbs":   {Short: "C", Label: "Carbs"},
	"fat":     {Short: "F", Label: "Fat"},
	"fiber":   {Short: "Fi", Label: "Fiber"},
	"sugar":   {Short: "S", Label: "Sugar"},
}

var MacroGoalModes = map[string]string{
	"calories": "limit",
	"protein":  "target",
	"carbs":    "limit",
	"fat":      "limit",
	"fiber":    "target",
	"sugar":    "limit",
}

var DotStatusRank = map[string]int{
	"none": 0, "zero": 1, "under": 2, "over": 3, "over_threshold": 4,
}

// MacroUser is a minimal interface for macro functions.
// Works with both model.User and linked user data.
type MacroUser struct {
	MacrosEnabled map[string]any
	MacroGoals    map[string]any
	DailyGoal     *int
	GoalThreshold int
}

func ParseMacroUser(macrosEnabledJSON, macroGoalsJSON json.RawMessage, dailyGoal *int, goalThreshold int) MacroUser {
	me := make(map[string]any)
	mg := make(map[string]any)
	json.Unmarshal(macrosEnabledJSON, &me)
	json.Unmarshal(macroGoalsJSON, &mg)
	return MacroUser{MacrosEnabled: me, MacroGoals: mg, DailyGoal: dailyGoal, GoalThreshold: goalThreshold}
}

func GetEnabledMacros(u MacroUser) []string {
	result := make([]string, 0)
	for _, key := range MacroKeys {
		if v, ok := u.MacrosEnabled[key]; ok && v == true {
			result = append(result, key)
		}
	}
	return result
}

func GetMacroGoals(u MacroUser) map[string]int {
	enabled := GetEnabledMacros(u)
	result := make(map[string]int)
	for _, key := range enabled {
		if v := getGoalValue(u.MacroGoals, key); v > 0 {
			result[key] = v
		}
	}
	return result
}

func GetMacroModes(u MacroUser) map[string]string {
	result := make(map[string]string)
	keys := append([]string{"calories"}, MacroKeys...)
	for _, key := range keys {
		modeKey := key + "_mode"
		if v, ok := u.MacroGoals[modeKey].(string); ok && (v == "limit" || v == "target") {
			result[key] = v
		} else if def, ok := MacroGoalModes[key]; ok {
			result[key] = def
		} else {
			result[key] = "limit"
		}
	}
	return result
}

func GetCalorieGoal(u MacroUser) *int {
	if v := getGoalValue(u.MacroGoals, "calories"); v > 0 {
		return &v
	}
	return u.DailyGoal
}

type MacroStatus struct {
	StatusClass string `json:"statusClass"`
	StatusText  string `json:"statusText"`
}

func ComputeMacroStatus(total int, goal *int, mode string, threshold int) MacroStatus {
	if goal == nil || *goal == 0 {
		return MacroStatus{StatusClass: "", StatusText: "No goal set"}
	}
	g := *goal

	if mode == "target" {
		if total >= g {
			over := total - g
			if over > 0 {
				return MacroStatus{StatusClass: "macro-stat--success", StatusText: strconv.Itoa(over) + " over target"}
			}
			return MacroStatus{StatusClass: "macro-stat--success", StatusText: "Goal met"}
		}
		under := g - total
		if under*100 > g*threshold {
			return MacroStatus{StatusClass: "macro-stat--danger", StatusText: strconv.Itoa(under) + " remaining"}
		}
		return MacroStatus{StatusClass: "macro-stat--warning", StatusText: strconv.Itoa(under) + " remaining"}
	}

	// Limit mode
	if total <= g {
		return MacroStatus{StatusClass: "macro-stat--success", StatusText: strconv.Itoa(g-total) + " remaining"}
	}
	over := total - g
	if over*100 > g*threshold {
		return MacroStatus{StatusClass: "macro-stat--danger", StatusText: strconv.Itoa(over) + " over"}
	}
	return MacroStatus{StatusClass: "macro-stat--warning", StatusText: strconv.Itoa(over) + " over"}
}

func ComputeDotStatus(statusClass string) string {
	switch statusClass {
	case "macro-stat--success":
		return "under"
	case "macro-stat--danger":
		return "over_threshold"
	case "macro-stat--warning":
		return "over"
	default:
		return "over"
	}
}

func WorstDotStatus(statuses []string) string {
	worst := "none"
	for _, s := range statuses {
		if DotStatusRank[s] > DotStatusRank[worst] {
			worst = s
		}
	}
	return worst
}

func IsAutoCalcCalories(u MacroUser) bool {
	v, _ := u.MacrosEnabled["auto_calc_calories"].(bool)
	return v
}

func ComputeCaloriesFromMacros(protein, carbs, fat int) *int {
	if protein == 0 && carbs == 0 && fat == 0 {
		return nil
	}
	result := protein*4 + carbs*4 + fat*9
	return &result
}

func GetMacroTotalsByDate(ctx context.Context, pool *pgxpool.Pool, userID int, oldest, newest string) (map[string]map[string]int, error) {
	rows, err := pool.Query(ctx, `
		SELECT entry_date,
			COALESCE(SUM(protein_g), 0) AS protein,
			COALESCE(SUM(carbs_g), 0) AS carbs,
			COALESCE(SUM(fat_g), 0) AS fat,
			COALESCE(SUM(fiber_g), 0) AS fiber,
			COALESCE(SUM(sugar_g), 0) AS sugar
		FROM calorie_entries
		WHERE user_id = $1 AND entry_date BETWEEN $2 AND $3
		GROUP BY entry_date`, userID, oldest, newest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string]map[string]int)
	for rows.Next() {
		var date string
		var protein, carbs, fat, fiber, sugar int
		if err := rows.Scan(&date, &protein, &carbs, &fat, &fiber, &sugar); err != nil {
			continue
		}
		result[date] = map[string]int{
			"protein": protein, "carbs": carbs, "fat": fat, "fiber": fiber, "sugar": sugar,
		}
	}
	return result, nil
}

func getGoalValue(goals map[string]any, key string) int {
	if goals == nil {
		return 0
	}
	v, ok := goals[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	}
	return 0
}
