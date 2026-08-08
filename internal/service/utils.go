package service

import (
	"math"
	"strconv"
	"strings"
	"time"
)

func FormatDateInTz(t time.Time, tz string) string {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return t.UTC().Format("2006-01-02")
	}
	return t.In(loc).Format("2006-01-02")
}

func FormatTimeInTz(t time.Time, tz string) string {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return t.UTC().Format("15:04")
	}
	return t.In(loc).Format("15:04")
}

type ParseWeightResult struct {
	Ok    bool
	Value float64
}

func ParseWeight(input string) ParseWeightResult {
	input = strings.TrimSpace(input)
	if input == "" {
		return ParseWeightResult{Ok: false}
	}
	normalized := strings.Replace(input, ",", ".", 1)
	if len(normalized) > 12 {
		return ParseWeightResult{Ok: false}
	}
	val, err := strconv.ParseFloat(normalized, 64)
	if err != nil || val <= 0 || val > 1500 || math.IsInf(val, 0) || math.IsNaN(val) {
		return ParseWeightResult{Ok: false}
	}
	// Re-check the lower bound *after* rounding. A positive input below half
	// the rounding granularity ("0.004") clears `val <= 0` and then rounds to
	// exactly 0, which the weight_entries_positive CHECK rejects — a 500 from
	// the database instead of a 400 here. Ok == true must imply Value > 0.
	// The upper bound stays pre-rounding on purpose: "1500.004" is out of
	// range as typed, and the parser is strict at both ends.
	rounded := math.Round(val*100) / 100
	if rounded <= 0 {
		return ParseWeightResult{Ok: false}
	}
	return ParseWeightResult{Ok: true, Value: rounded}
}

// MaxBodyFatPct bounds an accepted body-fat reading. It is deliberately loose —
// the highest percentages ever recorded are around 70 — and matches the
// weight_entries_body_fat_range CHECK so an out-of-bounds value fails as a 400
// here rather than a 500 from the database.
const MaxBodyFatPct = 75.0

// ParseBodyFat parses a body-fat percentage, accepting the same comma-decimal
// and stringified-number inputs as ParseWeight. Rounds to one decimal to match
// the NUMERIC(4,1) column.
//
// Like ParseWeight it validates the rounded value against the lower bound, so
// ok == true always implies pct > 0 — the contract the
// weight_entries_body_fat_range CHECK depends on.
func ParseBodyFat(input string) (float64, bool) {
	input = strings.TrimSpace(input)
	if input == "" || len(input) > 12 {
		return 0, false
	}
	val, err := strconv.ParseFloat(strings.Replace(input, ",", ".", 1), 64)
	if err != nil || val <= 0 || val > MaxBodyFatPct || math.IsInf(val, 0) || math.IsNaN(val) {
		return 0, false
	}
	rounded := math.Round(val*10) / 10
	if rounded <= 0 {
		return 0, false
	}
	return rounded, true
}

func SubtractDaysUTC(dateStr string, days int) string {
	t, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return dateStr
	}
	return t.AddDate(0, 0, -days).Format("2006-01-02")
}

func BuildDayOptionsBetween(startDateStr, endDateStr string, maxDays int) []string {
	start, err1 := time.Parse("2006-01-02", startDateStr)
	end, err2 := time.Parse("2006-01-02", endDateStr)
	if err1 != nil || err2 != nil {
		return nil
	}

	var days []string
	cursor := end
	for i := 0; i < maxDays; i++ {
		if cursor.Before(start) {
			break
		}
		days = append(days, cursor.Format("2006-01-02"))
		cursor = cursor.AddDate(0, 0, -1)
	}
	return days
}

func ContainsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
