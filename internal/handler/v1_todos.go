package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"schautrack/internal/apierr"
	"schautrack/internal/service"
)

// v1Todo is the public representation of a recurring todo.
//
// Schedule is passed through as raw JSON rather than being re-modelled here:
// service.ValidateSchedule owns its shape, and re-declaring it in the handler
// would create a second definition to keep in sync.
type v1Todo struct {
	ID        int             `json:"id"`
	Name      string          `json:"name"`
	Schedule  json.RawMessage `json:"schedule"`
	TimeOfDay *string         `json:"time_of_day"`
	SortOrder int             `json:"sort_order"`
	CreatedAt time.Time       `json:"created_at"`
}

const todoSelect = `id, name, schedule, time_of_day, sort_order, created_at`

func scanTodo(row pgx.Row) (*v1Todo, error) {
	var t v1Todo
	if err := row.Scan(&t.ID, &t.Name, &t.Schedule, &t.TimeOfDay, &t.SortOrder, &t.CreatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

// ListTodosV1 handles GET /api/v1/todos — every non-archived todo definition.
func (h *V1Handler) ListTodosV1(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Pool.Query(r.Context(),
		"SELECT "+todoSelect+" FROM todos WHERE user_id = $1 AND archived = FALSE ORDER BY sort_order, id",
		v1User(r).ID)
	if err != nil {
		apierr.Write(w, r, dbFail("list todos", err))
		return
	}
	defer rows.Close()

	out := []v1Todo{}
	for rows.Next() {
		t, err := scanTodo(rows)
		if err != nil {
			apierr.Write(w, r, dbFail("scan todo", err))
			return
		}
		out = append(out, *t)
	}
	if err := rows.Err(); err != nil {
		apierr.Write(w, r, dbFail("iterate todos", err))
		return
	}
	writeV1(w, http.StatusOK, v1List[v1Todo]{Data: out})
}

// v1TodoDay is a todo as it applies to one particular date: the definition
// plus the state that only exists relative to a day.
type v1TodoDay struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	TimeOfDay   *string `json:"time_of_day"`
	Completed   bool    `json:"completed"`
	Streak      int     `json:"streak"`
	MissedSince *string `json:"missed_since"`
}

// TodosForDayV1 handles GET /api/v1/todos/day/{date}: the todos actually
// scheduled for that date, with completion, streak, and missed-since.
//
// This is the endpoint an automation wants ("what do I still have to do
// today?"); GET /todos returns definitions, which is a different question.
func (h *V1Handler) TodosForDayV1(w http.ResponseWriter, r *http.Request) {
	date, prob := pathDate(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	tgt, prob := h.resolveTarget(r, service.ShareTodos)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}

	rows, err := h.Pool.Query(r.Context(),
		"SELECT id, name, schedule, time_of_day FROM todos WHERE user_id = $1 AND archived = FALSE ORDER BY sort_order, id",
		tgt.User.ID)
	if err != nil {
		apierr.Write(w, r, dbFail("list todos for day", err))
		return
	}
	defer rows.Close()

	type todoRow struct {
		ID        int
		Name      string
		Schedule  json.RawMessage
		TimeOfDay *string
	}
	var scheduled []todoRow
	for rows.Next() {
		var t todoRow
		if err := rows.Scan(&t.ID, &t.Name, &t.Schedule, &t.TimeOfDay); err != nil {
			apierr.Write(w, r, dbFail("scan todo for day", err))
			return
		}
		if service.IsScheduledForDate(t.Schedule, date) {
			scheduled = append(scheduled, t)
		}
	}
	if err := rows.Err(); err != nil {
		apierr.Write(w, r, dbFail("iterate todos for day", err))
		return
	}

	// Timed todos first in chronological order, then untimed — the same
	// ordering the UI uses, so an API client and the app agree on "next up".
	sort.SliceStable(scheduled, func(i, j int) bool {
		a, b := scheduled[i].TimeOfDay, scheduled[j].TimeOfDay
		if a != nil && b != nil {
			return *a < *b
		}
		return a != nil
	})

	out := []v1TodoDay{}
	if len(scheduled) > 0 {
		ids := make([]int, len(scheduled))
		for i, t := range scheduled {
			ids[i] = t.ID
		}

		// One query for all completion history up to the date; streaks are
		// computed in Go from it. Per-todo queries here would be N+1.
		hist, err := h.Pool.Query(r.Context(),
			`SELECT todo_id, completion_date FROM todo_completions
			 WHERE todo_id = ANY($1) AND completion_date <= $2
			 ORDER BY completion_date DESC`, ids, date)
		if err != nil {
			apierr.Write(w, r, dbFail("load completions", err))
			return
		}
		defer hist.Close()

		datesByTodo := map[int][]string{}
		doneToday := map[int]bool{}
		for hist.Next() {
			var id int
			var d string
			if err := hist.Scan(&id, &d); err != nil {
				apierr.Write(w, r, dbFail("scan completion", err))
				return
			}
			datesByTodo[id] = append(datesByTodo[id], d)
			if d == date {
				doneToday[id] = true
			}
		}
		if err := hist.Err(); err != nil {
			apierr.Write(w, r, dbFail("iterate completions", err))
			return
		}

		for _, t := range scheduled {
			streak, missed := service.ComputeStreak(t.Schedule, datesByTodo[t.ID], date)
			item := v1TodoDay{
				ID: t.ID, Name: t.Name, TimeOfDay: t.TimeOfDay,
				Completed: doneToday[t.ID], Streak: streak,
			}
			if missed != "" {
				item.MissedSince = &missed
			}
			out = append(out, item)
		}
	}
	writeV1(w, http.StatusOK, v1List[v1TodoDay]{Data: out})
}

type v1TodoInput struct {
	Name      string          `json:"name"`
	Schedule  json.RawMessage `json:"schedule"`
	TimeOfDay *string         `json:"time_of_day"`
}

// CreateTodoV1 handles POST /api/v1/todos.
func (h *V1Handler) CreateTodoV1(w http.ResponseWriter, r *http.Request) {
	var in v1TodoInput
	if prob := decodeV1(w, r, &in); prob != nil {
		apierr.Write(w, r, prob)
		return
	}

	name := truncateUTF8(strings.TrimSpace(in.Name), 100)
	if name == "" {
		apierr.Write(w, r, apierr.Unprocessable("A todo needs a name.",
			apierr.InvalidParam{Name: "name", Reason: "required"}))
		return
	}

	// ValidateSchedule takes `any`, so the raw JSON is unmarshalled generically
	// first. This keeps one schedule validator for both the app and the API.
	var scheduleAny any
	if len(in.Schedule) > 0 {
		if err := json.Unmarshal(in.Schedule, &scheduleAny); err != nil {
			apierr.Write(w, r, apierr.Unprocessable("The schedule is not valid JSON.",
				apierr.InvalidParam{Name: "schedule", Reason: "malformed"}))
			return
		}
	}
	sched := service.ValidateSchedule(scheduleAny)
	if !sched.Ok {
		apierr.Write(w, r, apierr.Unprocessable(sched.Error,
			apierr.InvalidParam{Name: "schedule", Reason: sched.Error}))
		return
	}

	user := v1User(r)
	var count int
	if err := h.Pool.QueryRow(r.Context(),
		"SELECT COUNT(*)::int FROM todos WHERE user_id = $1 AND archived = FALSE", user.ID).Scan(&count); err != nil {
		apierr.Write(w, r, dbFail("count todos", err))
		return
	}
	if count >= service.MaxTodos {
		apierr.Write(w, r, apierr.Conflict(
			fmt.Sprintf("You already have the maximum of %d todos.", service.MaxTodos)))
		return
	}

	var timeOfDay *string
	if in.TimeOfDay != nil {
		if timeOfDay = service.ValidateTimeOfDay(*in.TimeOfDay); timeOfDay == nil && strings.TrimSpace(*in.TimeOfDay) != "" {
			apierr.Write(w, r, apierr.Unprocessable("The time of day is not valid.",
				apierr.InvalidParam{Name: "time_of_day", Reason: "must be HH:MM"}))
			return
		}
	}

	t, err := scanTodo(h.Pool.QueryRow(r.Context(),
		"INSERT INTO todos (user_id, name, schedule, time_of_day, sort_order) VALUES ($1, $2, $3, $4, $5) RETURNING "+todoSelect,
		user.ID, name, sched.Schedule, timeOfDay, count))
	if err != nil {
		apierr.Write(w, r, dbFail("create todo", err))
		return
	}

	h.broadcastTodos(user.ID)
	w.Header().Set("Location", fmt.Sprintf("/api/v1/todos/%d", t.ID))
	writeV1(w, http.StatusCreated, t)
}

type v1TodoPatch struct {
	Name     *string         `json:"name"`
	Schedule json.RawMessage `json:"schedule"`
	// Optional so an explicit null can clear the time; see its doc comment.
	TimeOfDay Optional[string] `json:"time_of_day"`
}

// UpdateTodoV1 handles PATCH /api/v1/todos/{id}.
func (h *V1Handler) UpdateTodoV1(w http.ResponseWriter, r *http.Request) {
	id, prob := pathID(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	var in v1TodoPatch
	if prob := decodeV1(w, r, &in); prob != nil {
		apierr.Write(w, r, prob)
		return
	}

	var sets []string
	var args []any
	set := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}

	if in.Name != nil {
		name := truncateUTF8(strings.TrimSpace(*in.Name), 100)
		if name == "" {
			apierr.Write(w, r, apierr.Unprocessable("A todo needs a name.",
				apierr.InvalidParam{Name: "name", Reason: "must not be empty"}))
			return
		}
		set("name", name)
	}
	if len(in.Schedule) > 0 {
		var scheduleAny any
		if err := json.Unmarshal(in.Schedule, &scheduleAny); err != nil {
			apierr.Write(w, r, apierr.Unprocessable("The schedule is not valid JSON.",
				apierr.InvalidParam{Name: "schedule", Reason: "malformed"}))
			return
		}
		sched := service.ValidateSchedule(scheduleAny)
		if !sched.Ok {
			apierr.Write(w, r, apierr.Unprocessable(sched.Error,
				apierr.InvalidParam{Name: "schedule", Reason: sched.Error}))
			return
		}
		set("schedule", sched.Schedule)
	}
	if in.TimeOfDay.Set {
		if in.TimeOfDay.Value == nil {
			set("time_of_day", nil)
		} else {
			tod := service.ValidateTimeOfDay(*in.TimeOfDay.Value)
			if tod == nil {
				apierr.Write(w, r, apierr.Unprocessable("The time of day is not valid.",
					apierr.InvalidParam{Name: "time_of_day", Reason: "must be HH:MM"}))
				return
			}
			set("time_of_day", *tod)
		}
	}
	if len(sets) == 0 {
		apierr.Write(w, r, apierr.BadRequest("The request body contained no updatable fields."))
		return
	}

	user := v1User(r)
	args = append(args, id, user.ID)
	t, err := scanTodo(h.Pool.QueryRow(r.Context(), fmt.Sprintf(
		"UPDATE todos SET %s WHERE id = $%d AND user_id = $%d AND archived = FALSE RETURNING %s",
		strings.Join(sets, ", "), len(args)-1, len(args), todoSelect), args...))
	if err != nil {
		if err == pgx.ErrNoRows {
			apierr.Write(w, r, apierr.NotFound("No todo with that id."))
			return
		}
		apierr.Write(w, r, dbFail("update todo", err))
		return
	}

	h.broadcastTodos(user.ID)
	writeV1(w, http.StatusOK, t)
}

// DeleteTodoV1 handles DELETE /api/v1/todos/{id}.
//
// This archives rather than deletes, matching the app: completion history
// references the todo, and hard-deleting would take a user's streak record with
// it. Archived todos are invisible to every read endpoint, so the distinction
// is not observable through the API.
func (h *V1Handler) DeleteTodoV1(w http.ResponseWriter, r *http.Request) {
	id, prob := pathID(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	user := v1User(r)
	tag, err := h.Pool.Exec(r.Context(),
		"UPDATE todos SET archived = TRUE WHERE id = $1 AND user_id = $2 AND archived = FALSE", id, user.ID)
	if err != nil {
		apierr.Write(w, r, dbFail("delete todo", err))
		return
	}
	if tag.RowsAffected() == 0 {
		apierr.Write(w, r, apierr.NotFound("No todo with that id."))
		return
	}
	h.broadcastTodos(user.ID)
	noContent(w)
}

type v1CompletionInput struct {
	Completed bool `json:"completed"`
}

// SetTodoCompletionV1 handles PUT /api/v1/todos/{id}/completions/{date}.
//
// PUT with an explicit `completed` boolean, not a POST /toggle. Toggling is
// not idempotent: a retried request flips the state back, so a script that
// times out and retries silently un-completes the todo it just completed.
// Stating the desired state makes retries safe.
func (h *V1Handler) SetTodoCompletionV1(w http.ResponseWriter, r *http.Request) {
	id, prob := pathID(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	date := chi.URLParam(r, "date")
	if !isValidDate(date) {
		apierr.Write(w, r, apierr.BadRequest("The date must be in YYYY-MM-DD format."))
		return
	}
	var in v1CompletionInput
	if prob := decodeV1(w, r, &in); prob != nil {
		apierr.Write(w, r, prob)
		return
	}

	user := v1User(r)
	var owned bool
	if err := h.Pool.QueryRow(r.Context(),
		"SELECT EXISTS(SELECT 1 FROM todos WHERE id = $1 AND user_id = $2 AND archived = FALSE)",
		id, user.ID).Scan(&owned); err != nil {
		apierr.Write(w, r, dbFail("check todo ownership", err))
		return
	}
	if !owned {
		apierr.Write(w, r, apierr.NotFound("No todo with that id."))
		return
	}

	if in.Completed {
		if _, err := h.Pool.Exec(r.Context(),
			`INSERT INTO todo_completions (todo_id, user_id, completion_date)
			 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, id, user.ID, date); err != nil {
			apierr.Write(w, r, dbFail("complete todo", err))
			return
		}
	} else if _, err := h.Pool.Exec(r.Context(),
		"DELETE FROM todo_completions WHERE todo_id = $1 AND user_id = $2 AND completion_date = $3",
		id, user.ID, date); err != nil {
		apierr.Write(w, r, dbFail("uncomplete todo", err))
		return
	}

	h.broadcastTodos(user.ID)
	writeV1(w, http.StatusOK, map[string]any{
		"todo_id": id, "date": date, "completed": in.Completed,
	})
}

func (h *V1Handler) broadcastTodos(userID int) {
	if h.Broker != nil {
		h.Broker.BroadcastTodoChange(userID)
	}
}
