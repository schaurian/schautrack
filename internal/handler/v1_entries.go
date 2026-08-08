package handler

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"schautrack/internal/apierr"
	"schautrack/internal/service"
)

// v1Macros is the macro block of an entry. Every field is a pointer so an
// unrecorded macro serializes as null rather than as a misleading 0 — "I ate no
// protein" and "I did not record protein" are different claims.
type v1Macros struct {
	ProteinG *int `json:"protein_g"`
	CarbsG   *int `json:"carbs_g"`
	FatG     *int `json:"fat_g"`
	FiberG   *int `json:"fiber_g"`
	SugarG   *int `json:"sugar_g"`
}

// v1Entry is the public representation of a calorie entry.
//
// The column is called `amount` and the JSON field is called `calories`. The
// public name says what the number means; the internal one is a legacy the API
// has no reason to inherit.
type v1Entry struct {
	ID        int       `json:"id"`
	Date      string    `json:"date"`
	Calories  int       `json:"calories"`
	Name      *string   `json:"name"`
	Macros    v1Macros  `json:"macros"`
	CreatedAt time.Time `json:"created_at"`

	// LocalTime is created_at rendered in the user's timezone. Clients that
	// just want to show "07:12" should not have to re-derive the user's zone.
	LocalTime string `json:"local_time"`
}

// entrySelect is the column list every entry query shares, in the order
// scanEntry expects.
const entrySelect = `id, entry_date, amount, entry_name, created_at,
	protein_g, carbs_g, fat_g, fiber_g, sugar_g`

func scanEntry(row pgx.Row, tz string) (*v1Entry, error) {
	var e v1Entry
	var created time.Time
	if err := row.Scan(&e.ID, &e.Date, &e.Calories, &e.Name, &created,
		&e.Macros.ProteinG, &e.Macros.CarbsG, &e.Macros.FatG,
		&e.Macros.FiberG, &e.Macros.SugarG); err != nil {
		return nil, err
	}
	e.CreatedAt = created
	e.LocalTime = service.FormatTimeInTz(created, tz)
	return &e, nil
}

// ListEntries handles GET /api/v1/entries.
//
// Filters: date (exact day), from/to (inclusive range), limit, cursor.
func (h *V1Handler) ListEntries(w http.ResponseWriter, r *http.Request) {
	date, prob := queryDate(r, "date")
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	from, prob := queryDate(r, "from")
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	to, prob := queryDate(r, "to")
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	if date != "" && (from != "" || to != "") {
		apierr.Write(w, r, apierr.BadRequest(`Use either "date" or "from"/"to", not both.`))
		return
	}
	if from != "" && to != "" && from > to {
		apierr.Write(w, r, apierr.Unprocessable(`"from" must not be after "to".`,
			apierr.InvalidParam{Name: "from", Reason: "after to"}))
		return
	}
	limit, prob := queryLimit(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	cur, prob := queryCursor(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}

	tgt, prob := h.resolveTarget(r, service.ShareNutrition)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	where := []string{"user_id = $1"}
	args := []any{tgt.User.ID}
	add := func(clause string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if date != "" {
		add("entry_date = $%d", date)
	}
	if from != "" {
		add("entry_date >= $%d", from)
	}
	if to != "" {
		add("entry_date <= $%d", to)
	}
	if cur != nil {
		// Strictly "older than the cursor row" in the (date DESC, id DESC)
		// ordering. The row comparison is what makes this a keyset seek rather
		// than a scan-and-skip.
		args = append(args, cur.Date, cur.ID)
		where = append(where, fmt.Sprintf("(entry_date, id) < ($%d::date, $%d)", len(args)-1, len(args)))
	}

	// Fetch one extra row to learn whether another page exists without a
	// second COUNT query.
	args = append(args, limit+1)
	q := fmt.Sprintf(
		"SELECT %s FROM calorie_entries WHERE %s ORDER BY entry_date DESC, id DESC LIMIT $%d",
		entrySelect, strings.Join(where, " AND "), len(args))

	rows, err := h.Pool.Query(r.Context(), q, args...)
	if err != nil {
		apierr.Write(w, r, dbFail("list entries", err))
		return
	}
	defer rows.Close()

	tz := tgt.tz()
	entries := []v1Entry{}
	for rows.Next() {
		e, err := scanEntry(rows, tz)
		if err != nil {
			apierr.Write(w, r, dbFail("scan entry", err))
			return
		}
		entries = append(entries, *e)
	}
	if err := rows.Err(); err != nil {
		apierr.Write(w, r, dbFail("iterate entries", err))
		return
	}

	hasMore := len(entries) > limit
	if hasMore {
		entries = entries[:limit]
	}
	out := v1List[v1Entry]{Data: entries, HasMore: &hasMore}
	if hasMore {
		last := entries[len(entries)-1]
		next := encodeCursor(cursor{Date: last.Date, ID: last.ID})
		out.NextCursor = &next
	}
	writeV1(w, http.StatusOK, out)
}

// GetEntryV1 handles GET /api/v1/entries/{id}.
//
// It honours ?user= for the same reason GET /entries does, and it has to: the
// list hands out ids, and an id from a linked account's list would 404 here if
// this looked the row up under the caller's own id. The list-then-fetch pattern
// has to work across the pair or the parameter is a trap.
//
// resolveTarget is the authorization boundary — the row is still scoped to a
// single user_id, so an id belonging to an account that is not linked (or does
// not share nutrition) is never readable.
func (h *V1Handler) GetEntryV1(w http.ResponseWriter, r *http.Request) {
	id, prob := pathID(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	tgt, prob := h.resolveTarget(r, service.ShareNutrition)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	row := h.Pool.QueryRow(r.Context(),
		"SELECT "+entrySelect+" FROM calorie_entries WHERE id = $1 AND user_id = $2", id, tgt.User.ID)

	e, err := scanEntry(row, tgt.tz())
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			apierr.Write(w, r, apierr.NotFound("No entry with that id."))
			return
		}
		apierr.Write(w, r, dbFail("get entry", err))
		return
	}
	writeV1(w, http.StatusOK, e)
}

// v1EntryInput is the POST body. Calories and every macro are pointers so the
// handler can tell "absent" from "explicitly zero" — the difference between
// leaving a field alone and clearing it.
type v1EntryInput struct {
	Date     *string `json:"date"`
	Calories *int    `json:"calories"`
	Name     *string `json:"name"`
	ProteinG *int    `json:"protein_g"`
	CarbsG   *int    `json:"carbs_g"`
	FatG     *int    `json:"fat_g"`
	FiberG   *int    `json:"fiber_g"`
	SugarG   *int    `json:"sugar_g"`
}

func (in v1EntryInput) macroPairs() []struct {
	Key string
	Val *int
} {
	return []struct {
		Key string
		Val *int
	}{
		{"protein", in.ProteinG}, {"carbs", in.CarbsG}, {"fat", in.FatG},
		{"fiber", in.FiberG}, {"sugar", in.SugarG},
	}
}

// validateMacros bounds-checks every supplied macro, collecting ALL violations
// rather than returning on the first. A script fixing one field at a time
// across five round-trips is a bad API.
func (in v1EntryInput) validateMacros() []apierr.InvalidParam {
	var bad []apierr.InvalidParam
	for _, m := range in.macroPairs() {
		if m.Val == nil {
			continue
		}
		if *m.Val < 0 || *m.Val > MaxEntryMacro {
			bad = append(bad, apierr.InvalidParam{
				Name:   m.Key + "_g",
				Reason: fmt.Sprintf("must be between 0 and %d", MaxEntryMacro),
			})
		}
	}
	return bad
}

// CreateEntryV1 handles POST /api/v1/entries.
func (h *V1Handler) CreateEntryV1(w http.ResponseWriter, r *http.Request) {
	var in v1EntryInput
	if prob := decodeV1(w, r, &in); prob != nil {
		apierr.Write(w, r, prob)
		return
	}

	date := v1Today(r)
	if in.Date != nil {
		if !isValidDate(*in.Date) {
			apierr.Write(w, r, apierr.Unprocessable("The date is not a valid calendar date.",
				apierr.InvalidParam{Name: "date", Reason: "must be YYYY-MM-DD"}))
			return
		}
		date = *in.Date
	}

	if bad := in.validateMacros(); bad != nil {
		apierr.Write(w, r, apierr.Unprocessable("One or more macro values are out of range.", bad...))
		return
	}

	user := v1User(r)
	mu := service.ParseMacroUser(user.MacrosEnabled, user.MacroGoals, user.DailyGoal, user.GoalThreshold)

	calories := 0
	if in.Calories != nil {
		if !entryCaloriesInRange(*in.Calories) {
			apierr.Write(w, r, apierr.Unprocessable("The calorie value is out of range.",
				apierr.InvalidParam{
					Name:   "calories",
					Reason: fmt.Sprintf("must be between -%d and %d", MaxEntryCalories, MaxEntryCalories),
				}))
			return
		}
		calories = *in.Calories
	}

	// When the user has auto-calc enabled, macros are authoritative and a
	// supplied calorie value is derived rather than trusted — mirroring what
	// the app itself does, so an entry created via the API is indistinguishable
	// from one created in the UI.
	hasMacros := false
	for _, m := range in.macroPairs() {
		if m.Val != nil {
			hasMacros = true
		}
	}
	if service.IsAutoCalcCalories(mu) && hasMacros {
		if computed := service.ComputeCaloriesFromMacros(
			intOrZero(in.ProteinG), intOrZero(in.CarbsG), intOrZero(in.FatG)); computed != nil {
			if !entryCaloriesInRange(*computed) {
				apierr.Write(w, r, apierr.Unprocessable(
					fmt.Sprintf("Calories computed from these macros exceed the maximum of %d.", MaxEntryCalories),
					apierr.InvalidParam{Name: "calories", Reason: "computed value out of range"}))
				return
			}
			calories = *computed
		}
	}

	if in.Calories == nil && !hasMacros {
		apierr.Write(w, r, apierr.Unprocessable(
			"An entry needs at least a calorie value or one macro.",
			apierr.InvalidParam{Name: "calories", Reason: "required when no macros are given"}))
		return
	}

	name := ""
	if in.Name != nil {
		name = truncateUTF8(strings.TrimSpace(*in.Name), 120)
	}

	cols := []string{"user_id", "entry_date", "amount", "entry_name"}
	vals := []string{"$1", "$2", "$3", "$4"}
	args := []any{user.ID, date, calories, nilString(name)}
	for _, m := range in.macroPairs() {
		if m.Val == nil {
			continue
		}
		args = append(args, *m.Val)
		cols = append(cols, m.Key+"_g")
		vals = append(vals, fmt.Sprintf("$%d", len(args)))
	}

	q := fmt.Sprintf("INSERT INTO calorie_entries (%s) VALUES (%s) RETURNING %s",
		strings.Join(cols, ", "), strings.Join(vals, ", "), entrySelect)
	e, err := scanEntry(h.Pool.QueryRow(r.Context(), q, args...), v1Tz(r))
	if err != nil {
		apierr.Write(w, r, dbFail("create entry", err))
		return
	}

	h.broadcastEntries(user.ID)
	w.Header().Set("Location", fmt.Sprintf("/api/v1/entries/%d", e.ID))
	writeV1(w, http.StatusCreated, e)
}

// v1EntryPatch is the PATCH body. An absent field means "leave alone", a
// present one means "set to this", and an explicit null clears the name or a
// macro. Optional is what makes those three cases distinguishable — see its
// doc comment for why a plain **T does not.
type v1EntryPatch struct {
	Date     *string          `json:"date"`
	Calories *int             `json:"calories"`
	Name     Optional[string] `json:"name"`
	ProteinG Optional[int]    `json:"protein_g"`
	CarbsG   Optional[int]    `json:"carbs_g"`
	FatG     Optional[int]    `json:"fat_g"`
	FiberG   Optional[int]    `json:"fiber_g"`
	SugarG   Optional[int]    `json:"sugar_g"`
}

// UpdateEntryV1 handles PATCH /api/v1/entries/{id}.
func (h *V1Handler) UpdateEntryV1(w http.ResponseWriter, r *http.Request) {
	id, prob := pathID(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	var in v1EntryPatch
	if prob := decodeV1(w, r, &in); prob != nil {
		apierr.Write(w, r, prob)
		return
	}

	user := v1User(r)
	mu := service.ParseMacroUser(user.MacrosEnabled, user.MacroGoals, user.DailyGoal, user.GoalThreshold)
	autoCalc := service.IsAutoCalcCalories(mu)

	var sets []string
	var args []any
	set := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}

	if in.Date != nil {
		if !isValidDate(*in.Date) {
			apierr.Write(w, r, apierr.Unprocessable("The date is not a valid calendar date.",
				apierr.InvalidParam{Name: "date", Reason: "must be YYYY-MM-DD"}))
			return
		}
		set("entry_date", *in.Date)
	}
	if in.Name.Set {
		if in.Name.Value == nil {
			set("entry_name", nil)
		} else {
			set("entry_name", nilString(truncateUTF8(strings.TrimSpace(*in.Name.Value), 120)))
		}
	}
	if in.Calories != nil {
		if autoCalc {
			apierr.Write(w, r, apierr.Unprocessable(
				"Calories are computed from macros for this account and cannot be set directly.",
				apierr.InvalidParam{Name: "calories", Reason: "read-only while auto-calc is enabled"}))
			return
		}
		if !entryCaloriesInRange(*in.Calories) {
			apierr.Write(w, r, apierr.Unprocessable("The calorie value is out of range.",
				apierr.InvalidParam{
					Name:   "calories",
					Reason: fmt.Sprintf("must be between -%d and %d", MaxEntryCalories, MaxEntryCalories),
				}))
			return
		}
		set("amount", *in.Calories)
	}

	macros := []struct {
		Key string
		Val Optional[int]
	}{
		{"protein", in.ProteinG}, {"carbs", in.CarbsG}, {"fat", in.FatG},
		{"fiber", in.FiberG}, {"sugar", in.SugarG},
	}
	var bad []apierr.InvalidParam
	for _, m := range macros {
		if !m.Val.Set {
			continue
		}
		if m.Val.Value == nil {
			set(m.Key+"_g", nil)
			continue
		}
		if v := *m.Val.Value; v < 0 || v > MaxEntryMacro {
			bad = append(bad, apierr.InvalidParam{
				Name:   m.Key + "_g",
				Reason: fmt.Sprintf("must be between 0 and %d", MaxEntryMacro),
			})
			continue
		}
		set(m.Key+"_g", *m.Val.Value)
	}
	if bad != nil {
		apierr.Write(w, r, apierr.Unprocessable("One or more macro values are out of range.", bad...))
		return
	}
	if len(sets) == 0 {
		apierr.Write(w, r, apierr.BadRequest("The request body contained no updatable fields."))
		return
	}

	// The field update and the auto-calc recompute run in one transaction, so
	// a rejected computed amount cannot leave macros committed against a stale
	// calorie value.
	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		apierr.Write(w, r, dbFail("begin update entry", err))
		return
	}
	defer tx.Rollback(r.Context())

	args = append(args, id, user.ID)
	q := fmt.Sprintf("UPDATE calorie_entries SET %s WHERE id = $%d AND user_id = $%d RETURNING %s",
		strings.Join(sets, ", "), len(args)-1, len(args), entrySelect)

	tz := v1Tz(r)
	e, err := scanEntry(tx.QueryRow(r.Context(), q, args...), tz)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			apierr.Write(w, r, apierr.NotFound("No entry with that id."))
			return
		}
		apierr.Write(w, r, dbFail("update entry", err))
		return
	}

	if autoCalc {
		if computed := service.ComputeCaloriesFromMacros(
			intOrZero(e.Macros.ProteinG), intOrZero(e.Macros.CarbsG), intOrZero(e.Macros.FatG)); computed != nil {
			if !entryCaloriesInRange(*computed) {
				apierr.Write(w, r, apierr.Unprocessable(
					fmt.Sprintf("Calories computed from these macros exceed the maximum of %d.", MaxEntryCalories),
					apierr.InvalidParam{Name: "calories", Reason: "computed value out of range"}))
				return
			}
			if _, err := tx.Exec(r.Context(),
				"UPDATE calorie_entries SET amount = $1 WHERE id = $2 AND user_id = $3",
				*computed, id, user.ID); err != nil {
				apierr.Write(w, r, dbFail("auto-calc entry", err))
				return
			}
			e.Calories = *computed
		}
	}

	if err := tx.Commit(r.Context()); err != nil {
		apierr.Write(w, r, dbFail("commit update entry", err))
		return
	}

	h.broadcastEntries(user.ID)
	writeV1(w, http.StatusOK, e)
}

// DeleteEntryV1 handles DELETE /api/v1/entries/{id}.
func (h *V1Handler) DeleteEntryV1(w http.ResponseWriter, r *http.Request) {
	id, prob := pathID(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	user := v1User(r)
	tag, err := h.Pool.Exec(r.Context(),
		"DELETE FROM calorie_entries WHERE id = $1 AND user_id = $2", id, user.ID)
	if err != nil {
		apierr.Write(w, r, dbFail("delete entry", err))
		return
	}
	if tag.RowsAffected() == 0 {
		apierr.Write(w, r, apierr.NotFound("No entry with that id."))
		return
	}
	h.broadcastEntries(user.ID)
	noContent(w)
}

// broadcastEntries pushes an SSE update so an open browser tab reflects an
// API-driven change immediately. The nil guard keeps handlers constructible
// without a broker in tests.
func (h *V1Handler) broadcastEntries(userID int) {
	if h.Broker != nil {
		h.Broker.BroadcastEntryChange(userID)
	}
}
