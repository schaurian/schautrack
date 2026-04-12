package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/sse"
)

type TodosHandler struct {
	Pool   *pgxpool.Pool
	Broker *sse.Broker
}

func (h *TodosHandler) ToggleEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled any `json:"enabled"`
	}
	ReadJSON(r, &body)
	enabled := body.Enabled == true || body.Enabled == "true"
	user := middleware.GetCurrentUser(r)
	if _, err := h.Pool.Exec(r.Context(), "UPDATE users SET todos_enabled = $1 WHERE id = $2", enabled, user.ID); err != nil {
		slog.Error("failed to toggle todos enabled", "error", err)
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": enabled})
}

func (h *TodosHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	rows, err := h.Pool.Query(r.Context(),
		"SELECT id, name, schedule, time_of_day, sort_order, created_at FROM todos WHERE user_id = $1 AND archived = FALSE ORDER BY sort_order, id",
		user.ID)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to load todos")
		return
	}
	defer rows.Close()

	var todos []map[string]any
	for rows.Next() {
		var id, sortOrder int
		var name string
		var schedule json.RawMessage
		var timeOfDay *string
		var createdAt time.Time
		rows.Scan(&id, &name, &schedule, &timeOfDay, &sortOrder, &createdAt)
		todos = append(todos, map[string]any{
			"id": id, "name": name, "schedule": json.RawMessage(schedule),
			"time_of_day": timeOfDay, "sort_order": sortOrder, "created_at": createdAt,
		})
	}
	if todos == nil {
		todos = []map[string]any{}
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "todos": todos})
}

func (h *TodosHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	name := strings.TrimSpace(fmt.Sprintf("%v", body["name"]))
	if len(name) > 100 {
		name = name[:100]
	}
	if name == "" {
		ErrorJSON(w, http.StatusBadRequest, "Name is required")
		return
	}

	result := service.ValidateSchedule(body["schedule"])
	if !result.Ok {
		ErrorJSON(w, http.StatusBadRequest, result.Error)
		return
	}

	user := middleware.GetCurrentUser(r)

	var count int
	if err := h.Pool.QueryRow(r.Context(), "SELECT COUNT(*)::int FROM todos WHERE user_id = $1 AND archived = FALSE", user.ID).Scan(&count); err != nil {
		slog.Error("failed to count todos", "error", err)
	}
	if count >= service.MaxTodos {
		ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Maximum %d todos allowed", service.MaxTodos))
		return
	}

	timeOfDayStr, _ := body["time_of_day"].(string)
	timeOfDay := service.ValidateTimeOfDay(timeOfDayStr)

	var id int
	var scheduleOut json.RawMessage
	var timeOfDayOut *string
	var sortOrderOut int
	var createdAtOut time.Time
	err := h.Pool.QueryRow(r.Context(),
		"INSERT INTO todos (user_id, name, schedule, time_of_day, sort_order) VALUES ($1, $2, $3, $4, $5) RETURNING id, schedule, time_of_day, sort_order, created_at",
		user.ID, name, result.Schedule, timeOfDay, count,
	).Scan(&id, &scheduleOut, &timeOfDayOut, &sortOrderOut, &createdAtOut)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to create todo")
		return
	}

	h.Broker.BroadcastTodoChange(user.ID)
	JSON(w, http.StatusOK, map[string]any{"ok": true, "todo": map[string]any{
		"id": id, "name": name, "schedule": json.RawMessage(scheduleOut),
		"time_of_day": timeOfDayOut, "sort_order": sortOrderOut, "created_at": createdAtOut,
	}})
}

func (h *TodosHandler) Update(w http.ResponseWriter, r *http.Request) {
	todoID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid todo id")
		return
	}

	var body map[string]any
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)
	var updates []string
	var values []any
	idx := 1

	if v, ok := body["name"]; ok {
		name := strings.TrimSpace(fmt.Sprintf("%v", v))
		if len(name) > 100 {
			name = name[:100]
		}
		if name == "" {
			ErrorJSON(w, http.StatusBadRequest, "Name is required")
			return
		}
		updates = append(updates, fmt.Sprintf("name = $%d", idx))
		values = append(values, name)
		idx++
	}

	if v, ok := body["schedule"]; ok {
		result := service.ValidateSchedule(v)
		if !result.Ok {
			ErrorJSON(w, http.StatusBadRequest, result.Error)
			return
		}
		updates = append(updates, fmt.Sprintf("schedule = $%d", idx))
		values = append(values, result.Schedule)
		idx++
	}

	if v, ok := body["time_of_day"]; ok {
		s, _ := v.(string)
		timeOfDay := service.ValidateTimeOfDay(s)
		updates = append(updates, fmt.Sprintf("time_of_day = $%d", idx))
		values = append(values, timeOfDay)
		idx++
	}

	if v, ok := body["sort_order"]; ok {
		if n, ok2 := v.(float64); ok2 {
			updates = append(updates, fmt.Sprintf("sort_order = $%d", idx))
			values = append(values, int(n))
			idx++
		}
	}

	if len(updates) == 0 {
		ErrorJSON(w, http.StatusBadRequest, "No updates provided")
		return
	}

	query := fmt.Sprintf("UPDATE todos SET %s WHERE id = $%d AND user_id = $%d AND archived = FALSE RETURNING id, name, schedule, time_of_day, sort_order",
		strings.Join(updates, ", "), idx, idx+1)
	values = append(values, todoID, user.ID)

	var id int
	var name string
	var schedule json.RawMessage
	var timeOfDay *string
	var sortOrder int
	err = h.Pool.QueryRow(r.Context(), query, values...).Scan(&id, &name, &schedule, &timeOfDay, &sortOrder)
	if err != nil {
		ErrorJSON(w, http.StatusNotFound, "Todo not found")
		return
	}

	h.Broker.BroadcastTodoChange(user.ID)
	JSON(w, http.StatusOK, map[string]any{"ok": true, "todo": map[string]any{
		"id": id, "name": name, "schedule": json.RawMessage(schedule),
		"time_of_day": timeOfDay, "sort_order": sortOrder,
	}})
}

func (h *TodosHandler) Delete(w http.ResponseWriter, r *http.Request) {
	todoID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid todo id")
		return
	}
	user := middleware.GetCurrentUser(r)
	tag, err := h.Pool.Exec(r.Context(), "UPDATE todos SET archived = TRUE WHERE id = $1 AND user_id = $2 AND archived = FALSE", todoID, user.ID)
	if err != nil || tag.RowsAffected() == 0 {
		ErrorJSON(w, http.StatusNotFound, "Todo not found")
		return
	}
	h.Broker.BroadcastTodoChange(user.ID)
	OkJSON(w)
}

func (h *TodosHandler) DayTodos(w http.ResponseWriter, r *http.Request) {
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

	var todosEnabled bool
	if err := h.Pool.QueryRow(r.Context(), "SELECT todos_enabled FROM users WHERE id = $1", targetUserID).Scan(&todosEnabled); err != nil {
		slog.Error("failed to check todos_enabled", "error", err)
	}
	if !todosEnabled {
		JSON(w, http.StatusOK, map[string]any{"ok": true, "todos": []any{}, "enabled": false})
		return
	}

	rows, err := h.Pool.Query(r.Context(),
		"SELECT id, name, schedule, time_of_day, sort_order FROM todos WHERE user_id = $1 AND archived = FALSE ORDER BY sort_order, id",
		targetUserID)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to load todos")
		return
	}
	defer rows.Close()

	type todoItem struct {
		ID        int
		Name      string
		Schedule  json.RawMessage
		TimeOfDay *string
		SortOrder int
	}
	var scheduled []todoItem
	for rows.Next() {
		var t todoItem
		rows.Scan(&t.ID, &t.Name, &t.Schedule, &t.TimeOfDay, &t.SortOrder)
		if service.IsScheduledForDate(t.Schedule, dateStr) {
			scheduled = append(scheduled, t)
		}
	}

	// Sort: with time first (chronologically), then timeless
	sort.SliceStable(scheduled, func(i, j int) bool {
		a, b := scheduled[i].TimeOfDay, scheduled[j].TimeOfDay
		if a != nil && b != nil {
			return *a < *b
		}
		if a != nil {
			return true
		}
		return false
	})

	// Fetch completions
	todoIDs := make([]int, len(scheduled))
	for i, t := range scheduled {
		todoIDs[i] = t.ID
	}
	completions := map[int]bool{}
	if len(todoIDs) > 0 {
		cRows, _ := h.Pool.Query(r.Context(), "SELECT todo_id FROM todo_completions WHERE todo_id = ANY($1) AND completion_date = $2", todoIDs, dateStr)
		if cRows != nil {
			defer cRows.Close()
			for cRows.Next() {
				var tid int
				cRows.Scan(&tid)
				completions[tid] = true
			}
		}
	}

	// Calculate streaks and missed days
	streaks := map[int]int{}
	missedSince := map[int]string{}
	if len(todoIDs) > 0 {
		sRows, _ := h.Pool.Query(r.Context(),
			"SELECT todo_id, completion_date FROM todo_completions WHERE todo_id = ANY($1) AND completion_date <= $2 ORDER BY completion_date DESC",
			todoIDs, dateStr)
		if sRows != nil {
			defer sRows.Close()
			datesByTodo := map[int][]string{}
			for sRows.Next() {
				var tid int
				var d string
				sRows.Scan(&tid, &d)
				datesByTodo[tid] = append(datesByTodo[tid], d)
			}
			for _, t := range scheduled {
				dates := datesByTodo[t.ID]
				streak := 0
				start, _ := time.Parse("2006-01-02", dateStr)
				for i := 0; i < 365; i++ {
					d := start.AddDate(0, 0, -i).Format("2006-01-02")
					if !service.IsScheduledForDate(t.Schedule, d) {
						continue
					}
					found := false
					for _, cd := range dates {
						if cd == d {
							found = true
							break
						}
					}
					if found {
						streak++
					} else {
						break
					}
				}
				streaks[t.ID] = streak

				// Compute missed_since: walk backwards from the day before dateStr
				// to find the earliest consecutive missed scheduled day
				if !completions[t.ID] {
					earliest := ""
					for i := 1; i <= 30; i++ {
						d := start.AddDate(0, 0, -i).Format("2006-01-02")
						if !service.IsScheduledForDate(t.Schedule, d) {
							continue
						}
						found := false
						for _, cd := range dates {
							if cd == d {
								found = true
								break
							}
						}
						if found {
							break
						}
						earliest = d
					}
					if earliest != "" {
						missedSince[t.ID] = earliest
					}
				}
			}
		}
	}

	var result []map[string]any
	for _, t := range scheduled {
		item := map[string]any{
			"id": t.ID, "name": t.Name, "time_of_day": t.TimeOfDay,
			"completed": completions[t.ID], "streak": streaks[t.ID],
		}
		if ms, ok := missedSince[t.ID]; ok {
			item["missed_since"] = ms
		}
		result = append(result, item)
	}
	if result == nil {
		result = []map[string]any{}
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": true, "todos": result})
}

func (h *TodosHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	todoID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid todo id")
		return
	}

	var body struct {
		Date string `json:"date"`
	}
	ReadJSON(r, &body)

	user := middleware.GetCurrentUser(r)
	dateStr := strings.TrimSpace(body.Date)
	if dateStr == "" {
		tz := getUserTimezone(r, user)
		dateStr = service.FormatDateInTz(time.Now(), tz)
	}
	if !dateRe.MatchString(dateStr) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid date")
		return
	}

	// Verify ownership
	var exists bool
	if err := h.Pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM todos WHERE id = $1 AND user_id = $2 AND archived = FALSE)", todoID, user.ID).Scan(&exists); err != nil {
		slog.Error("failed to verify todo ownership", "error", err)
	}
	if !exists {
		ErrorJSON(w, http.StatusNotFound, "Todo not found")
		return
	}

	// Toggle: try delete first
	tag, err := h.Pool.Exec(r.Context(), "DELETE FROM todo_completions WHERE todo_id = $1 AND completion_date = $2", todoID, dateStr)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to toggle todo")
		return
	}
	completed := false
	if tag.RowsAffected() == 0 {
		if _, err := h.Pool.Exec(r.Context(), "INSERT INTO todo_completions (todo_id, user_id, completion_date) VALUES ($1, $2, $3)", todoID, user.ID, dateStr); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Failed to toggle todo")
			return
		}
		completed = true
	}

	h.Broker.BroadcastTodoChange(user.ID)
	JSON(w, http.StatusOK, map[string]any{"ok": true, "completed": completed})
}

func (h *TodosHandler) Reorder(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Order []any `json:"order"`
	}
	if err := ReadJSON(r, &body); err != nil || body.Order == nil {
		ErrorJSON(w, http.StatusBadRequest, "Order must be an array of todo IDs")
		return
	}

	user := middleware.GetCurrentUser(r)
	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to reorder todos")
		return
	}
	defer tx.Rollback(r.Context())

	for i, v := range body.Order {
		id, ok := v.(float64)
		if !ok {
			continue
		}
		if _, err := tx.Exec(r.Context(), "UPDATE todos SET sort_order = $1 WHERE id = $2 AND user_id = $3", i, int(id), user.ID); err != nil {
			slog.Error("failed to update todo sort order", "error", err)
			ErrorJSON(w, http.StatusInternalServerError, "Failed to reorder todos")
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		slog.Error("failed to commit todo reorder", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to reorder todos")
		return
	}

	h.Broker.BroadcastTodoChange(user.ID)
	OkJSON(w)
}
