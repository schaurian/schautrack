package handler

import (
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/middleware"
	"schautrack/internal/service"
)

const (
	MaxHistoryDays   = 180
	DefaultRangeDays = 14
	MaxEntryCalories = 9999
	MaxEntryMacro    = 999
)

var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

type dailyStat struct {
	Date          string `json:"date"`
	Total         int    `json:"total"`
	Status        string `json:"status"`
	OverThreshold bool   `json:"overThreshold"`
}

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
		if err := rows.Scan(&date, &total); err != nil {
			continue
		}
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
