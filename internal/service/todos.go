package service

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxTodos = 20

type Schedule struct {
	Type string `json:"type"`
	Days []int  `json:"days,omitempty"`
}

func IsScheduledForDate(scheduleJSON json.RawMessage, dateStr string) bool {
	if len(scheduleJSON) == 0 || dateStr == "" {
		return false
	}
	var s Schedule
	if err := json.Unmarshal(scheduleJSON, &s); err != nil {
		return false
	}
	if s.Type == "daily" {
		return true
	}
	if s.Type == "weekdays" && len(s.Days) > 0 {
		t, err := time.Parse("2006-01-02", dateStr)
		if err != nil {
			return false
		}
		wd := int(t.Weekday()) // 0=Sun
		isoDay := wd
		if isoDay == 0 {
			isoDay = 7
		}
		for _, d := range s.Days {
			if d == isoDay {
				return true
			}
		}
	}
	return false
}

type ValidateScheduleResult struct {
	Ok       bool
	Schedule json.RawMessage
	Error    string
}

func ValidateSchedule(raw any) ValidateScheduleResult {
	m, ok := raw.(map[string]any)
	if !ok || m == nil {
		return ValidateScheduleResult{Ok: false, Error: "Schedule is required"}
	}

	typ, _ := m["type"].(string)
	if typ == "daily" {
		j, _ := json.Marshal(Schedule{Type: "daily"})
		return ValidateScheduleResult{Ok: true, Schedule: j}
	}
	if typ == "weekdays" {
		daysRaw, ok := m["days"].([]any)
		if !ok || len(daysRaw) == 0 {
			return ValidateScheduleResult{Ok: false, Error: "Weekday schedule requires at least one day"}
		}
		seen := map[int]bool{}
		var days []int
		for _, d := range daysRaw {
			var n int
			switch v := d.(type) {
			case float64:
				n = int(v)
			case int:
				n = v
			default:
				continue
			}
			if n >= 1 && n <= 7 && !seen[n] {
				days = append(days, n)
				seen[n] = true
			}
		}
		if len(days) == 0 {
			return ValidateScheduleResult{Ok: false, Error: "Invalid weekday values (must be 1-7)"}
		}
		j, _ := json.Marshal(Schedule{Type: "weekdays", Days: days})
		return ValidateScheduleResult{Ok: true, Schedule: j}
	}

	return ValidateScheduleResult{Ok: false, Error: "Invalid schedule type"}
}

var timeRe = regexp.MustCompile(`^(\d{1,2}):(\d{2})$`)

func ValidateTimeOfDay(raw string) *string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	m := timeRe.FindStringSubmatch(trimmed)
	if m == nil {
		return nil
	}
	h, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	if h < 0 || h > 23 || min < 0 || min > 59 {
		return nil
	}
	result := fmt.Sprintf("%02d:%02d", h, min)
	return &result
}
