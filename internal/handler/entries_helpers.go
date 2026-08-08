package handler

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"regexp"
	"strconv"
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
	// MaxEntryNameBytes bounds entry_name. Enforced in bytes rather than
	// runes because that is what the column is sized in.
	MaxEntryNameBytes = 120
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
	if endStr != "" && isValidDate(strings.TrimSpace(endStr)) {
		e := strings.TrimSpace(endStr)
		if e <= todayStr {
			endDate = e
		}
	}

	fallbackStart := service.SubtractDaysUTC(endDate, fallbackDays-1)
	startDate := fallbackStart
	if startStr != "" && isValidDate(strings.TrimSpace(startStr)) {
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

func getTotalsByDate(r *http.Request, pool *pgxpool.Pool, userID int, oldest, newest string) (map[string]int, error) {
	rows, err := pool.Query(r.Context(),
		"SELECT entry_date, SUM(amount) AS total FROM calorie_entries WHERE user_id = $1 AND entry_date BETWEEN $2 AND $3 GROUP BY entry_date",
		userID, oldest, newest)
	if err != nil {
		return nil, err
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
	// A mid-iteration error would otherwise silently yield partial totals
	// that callers present as complete data.
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// getTotalsAndMacrosByDate scans the calorie_entries range a single time and
// returns both the per-day calorie totals and the per-day macro totals. It
// replaces the two separate range scans (getTotalsByDate + GetMacroTotalsByDate)
// on the Dashboard's hot path. The macro map is always populated; callers with
// no macros enabled simply ignore it. The results are byte-for-byte identical to
// the two-query version (SUM(amount) and the COALESCE'd macro SUMs, grouped by
// entry_date over the same user_id/date range).
func getTotalsAndMacrosByDate(ctx context.Context, pool *pgxpool.Pool, userID int, oldest, newest string) (map[string]int, map[string]map[string]int, error) {
	rows, err := pool.Query(ctx, `
		SELECT entry_date,
			SUM(amount) AS total,
			COALESCE(SUM(protein_g), 0) AS protein,
			COALESCE(SUM(carbs_g), 0) AS carbs,
			COALESCE(SUM(fat_g), 0) AS fat,
			COALESCE(SUM(fiber_g), 0) AS fiber,
			COALESCE(SUM(sugar_g), 0) AS sugar
		FROM calorie_entries
		WHERE user_id = $1 AND entry_date BETWEEN $2 AND $3
		GROUP BY entry_date`, userID, oldest, newest)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	totals := map[string]int{}
	macros := make(map[string]map[string]int)
	for rows.Next() {
		var date string
		var total, protein, carbs, fat, fiber, sugar int
		if err := rows.Scan(&date, &total, &protein, &carbs, &fat, &fiber, &sugar); err != nil {
			continue
		}
		totals[date] = total
		macros[date] = map[string]int{
			"protein": protein, "carbs": carbs, "fat": fat, "fiber": fiber, "sugar": sugar,
		}
	}
	// Propagate mid-iteration errors instead of returning partial totals.
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return totals, macros, nil
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

// optionalString reads key out of a JSON body that was decoded into a
// map[string]any and reports the three states a field can be in: absent
// (present=false), explicitly null (present=true, value=nil), or present with
// a value (present=true, value non-nil).
//
// It is the map[string]any counterpart of Optional[T] (v1_common.go), which
// the v1 PATCH handlers use to make the same distinction from a typed struct.
// The legacy SPA surface decodes into a bare map, so the distinction has to be
// recovered from the map itself: a missing key is absent, and a key holding a
// nil interface value is an explicit JSON null.
//
// Checking that interface for nil BEFORE coercing is the whole point. The call
// sites used to do it the other way around — fmt.Sprintf("%v", v) first — which
// renders a JSON null as the literal string "<nil>". Some of them then compared
// against that "<nil>" sentinel to detect a null, and one (the entry-name path
// in UpdateEntry) did not, so POST /entries/:id/update with {"name": null}
// renamed the entry to the four characters <nil> instead of clearing it. The
// sentinel was never sound either way: a user who legitimately types <nil> as
// an entry name is indistinguishable from a null once the type is thrown away.
//
// The returned value is whitespace-trimmed. Non-string JSON values (numbers,
// booleans, objects, arrays) are still rendered with %v, matching what this
// loosely-typed surface has always accepted from clients that send numbers as
// numbers on one screen and as strings on another.
func optionalString(body map[string]any, key string) (value *string, present bool) {
	raw, present := body[key]
	if !present || raw == nil {
		return nil, present
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", raw))
	return &s, true
}

// optionalEntryName layers the entry-name rules on top of optionalString: cap
// the value at MaxEntryNameBytes on a UTF-8 rune boundary, then collapse an
// empty result to nil so the column is cleared rather than storing "".
//
// The three states map onto the column as:
//
//	present=false             -> key absent; leave the stored name alone
//	present=true, value=nil   -> clear the name (explicit null, "", or blanks)
//	present=true, value!=nil  -> set the name
func optionalEntryName(body map[string]any, key string) (value *string, present bool) {
	raw, present := optionalString(body, key)
	if !present || raw == nil {
		return nil, present
	}
	return nilString(truncateUTF8(*raw, MaxEntryNameBytes)), true
}

// buildEntryUpdates turns a decoded POST /entries/:id/update body into the SET
// fragments and bind values of the UPDATE statement, using $1..$n in the order
// the fragments are returned.
//
// It is deliberately pure — no request, no pool — so the absent/null/present
// semantics of every field can be asserted without a database. Needing one is
// exactly why the "<nil>" entry-name bug shipped untested.
//
// The third return value is a client-facing message, empty on success; a
// non-empty message always means 400. This mirrors parseSavedFoodPayload, the
// same-shaped validator on the saved-foods handler.
func buildEntryUpdates(body map[string]any, autoCalc bool) ([]string, []any, string) {
	var updates []string
	var values []any
	idx := 1

	if name, present := optionalEntryName(body, "name"); present {
		updates = append(updates, fmt.Sprintf("entry_name = $%d", idx))
		values = append(values, name)
		idx++
	}

	// When calories are auto-calculated from macros, an incoming amount is
	// ignored: the post-update recompute would immediately overwrite it.
	if raw, present := optionalString(body, "amount"); present && !autoCalc {
		amount := 0
		if raw != nil && *raw != "" && *raw != "0" {
			result := service.ParseAmount(*raw, MaxEntryCalories)
			if !result.Ok {
				return nil, nil, fmt.Sprintf("Calories must be between -%d and %d", MaxEntryCalories, MaxEntryCalories)
			}
			amount = result.Value
		}
		updates = append(updates, fmt.Sprintf("amount = $%d", idx))
		values = append(values, amount)
		idx++
	}

	for _, key := range service.MacroKeys {
		fieldName := key + "_g"
		raw, present := optionalString(body, fieldName)
		if !present {
			continue
		}
		// A cleared macro becomes NULL, not 0 — the column is nullable and
		// "no reading" is not the same as "zero grams". A literal "0" clears
		// too: this surface has always read an entered zero as "remove it",
		// which is what the SPA relies on (EntryList sends null for "0").
		var value any
		if raw != nil && *raw != "" && *raw != "0" {
			n, err := strconv.Atoi(*raw)
			if err != nil || n < 0 || n > MaxEntryMacro {
				return nil, nil, fmt.Sprintf("Macro values must be between 0 and %d", MaxEntryMacro)
			}
			value = n
		}
		updates = append(updates, fmt.Sprintf("%s = $%d", fieldName, idx))
		values = append(values, value)
		idx++
	}

	return updates, values, ""
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
