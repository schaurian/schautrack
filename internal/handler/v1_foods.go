package handler

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"schautrack/internal/apierr"
	"schautrack/internal/service"
)

// v1SavedFood is the public representation of a reusable quick-add food.
type v1SavedFood struct {
	ID         int        `json:"id"`
	Name       string     `json:"name"`
	Emoji      *string    `json:"emoji"`
	Calories   *int       `json:"calories"`
	Macros     v1Macros   `json:"macros"`
	UseCount   int        `json:"use_count"`
	LastUsedAt *time.Time `json:"last_used_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

const savedFoodSelect = `id, name, emoji, amount, protein_g, carbs_g, fat_g, fiber_g, sugar_g,
	use_count, last_used_at, created_at, updated_at`

// savedFoodRank is the ranking shared by both saved-food list endpoints:
// SavedFoodsHandler.List (the app) and ListSavedFoodsV1 (the API).
//
// It is one constant because the two must not drift. They previously
// disagreed on the final tiebreaker — the app used `id DESC`, v1 used `id`
// ascending — so two foods with the same use_count and last_used_at (both
// never used, which is every food right after you create a few) came back in
// opposite orders from the API and the app, despite v1 documenting itself as
// "ranked the way the app ranks them".
const savedFoodRank = `use_count DESC, last_used_at DESC NULLS LAST, id DESC`

func scanSavedFood(row pgx.Row) (*v1SavedFood, error) {
	var f v1SavedFood
	if err := row.Scan(&f.ID, &f.Name, &f.Emoji, &f.Calories,
		&f.Macros.ProteinG, &f.Macros.CarbsG, &f.Macros.FatG, &f.Macros.FiberG, &f.Macros.SugarG,
		&f.UseCount, &f.LastUsedAt, &f.CreatedAt, &f.UpdatedAt); err != nil {
		return nil, err
	}
	return &f, nil
}

// ListSavedFoodsV1 handles GET /api/v1/saved-foods, ranked the way the app
// ranks them: most-used first, then most-recently-used, then newest first.
//
// Deliberately unpaginated — it returns the account's complete set, always.
// Saved foods are hard-bounded: every insert path refuses at MaxSavedFoods
// (200), and 200 is also the largest page queryLimit would ever hand out, so a
// "page" could never have held a row the whole set does not. All the old
// `LIMIT $2` achieved was dropping everything past the 50-row default while
// v1List's has_more and next_cursor — both omitempty — stayed absent, leaving
// a caller with 60 foods no way to tell their 50-item response was partial.
// A syncing client reasonably concluded the missing 10 had been deleted.
//
// Reporting has_more instead would need a cursor to be actionable, and the
// (date, id) cursor here cannot encode a (use_count, last_used_at, id)
// position — machinery a 200-row ceiling does not justify. The other bounded
// collections, /todos and /links, already return everything with no
// pagination fields; this one now matches them, and matches the SavedFoodList
// schema, which never declared has_more or next_cursor in the first place.
//
// `limit` is consequently no longer read. Ignoring it can only ever return
// more than a caller asked for, never fewer rows than exist — the safe
// direction. It is dropped from this operation in the OpenAPI document.
func (h *V1Handler) ListSavedFoodsV1(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Pool.Query(r.Context(),
		"SELECT "+savedFoodSelect+` FROM saved_foods WHERE user_id = $1
		 ORDER BY `+savedFoodRank,
		v1User(r).ID)
	if err != nil {
		apierr.Write(w, r, dbFail("list saved foods", err))
		return
	}
	defer rows.Close()

	out := []v1SavedFood{}
	for rows.Next() {
		f, err := scanSavedFood(rows)
		if err != nil {
			apierr.Write(w, r, dbFail("scan saved food", err))
			return
		}
		out = append(out, *f)
	}
	if err := rows.Err(); err != nil {
		apierr.Write(w, r, dbFail("iterate saved foods", err))
		return
	}
	writeV1(w, http.StatusOK, v1List[v1SavedFood]{Data: out})
}

type v1SavedFoodInput struct {
	Name     string  `json:"name"`
	Emoji    *string `json:"emoji"`
	Calories *int    `json:"calories"`
	ProteinG *int    `json:"protein_g"`
	CarbsG   *int    `json:"carbs_g"`
	FatG     *int    `json:"fat_g"`
	FiberG   *int    `json:"fiber_g"`
	SugarG   *int    `json:"sugar_g"`
}

// validateFoodMacros bounds-checks macros, collecting every violation.
func validateFoodMacros(vals map[string]*int) []apierr.InvalidParam {
	var bad []apierr.InvalidParam
	for _, key := range service.MacroKeys {
		v := vals[key]
		if v == nil {
			continue
		}
		if *v < 0 || *v > MaxEntryMacro {
			bad = append(bad, apierr.InvalidParam{
				Name:   key + "_g",
				Reason: fmt.Sprintf("must be between 0 and %d", MaxEntryMacro),
			})
		}
	}
	return bad
}

// CreateSavedFoodV1 handles POST /api/v1/saved-foods.
func (h *V1Handler) CreateSavedFoodV1(w http.ResponseWriter, r *http.Request) {
	var in v1SavedFoodInput
	if prob := decodeV1(w, r, &in); prob != nil {
		apierr.Write(w, r, prob)
		return
	}

	name := truncateUTF8(strings.TrimSpace(in.Name), MaxSavedFoodName)
	if name == "" {
		apierr.Write(w, r, apierr.Unprocessable("A saved food needs a name.",
			apierr.InvalidParam{Name: "name", Reason: "required"}))
		return
	}
	if in.Calories != nil && !entryCaloriesInRange(*in.Calories) {
		apierr.Write(w, r, apierr.Unprocessable("The calorie value is out of range.",
			apierr.InvalidParam{
				Name:   "calories",
				Reason: fmt.Sprintf("must be between -%d and %d", MaxEntryCalories, MaxEntryCalories),
			}))
		return
	}
	macros := map[string]*int{
		"protein": in.ProteinG, "carbs": in.CarbsG, "fat": in.FatG,
		"fiber": in.FiberG, "sugar": in.SugarG,
	}
	if bad := validateFoodMacros(macros); bad != nil {
		apierr.Write(w, r, apierr.Unprocessable("One or more macro values are out of range.", bad...))
		return
	}

	var emoji *string
	if in.Emoji != nil {
		if e := truncateUTF8(strings.TrimSpace(*in.Emoji), MaxSavedFoodEmoji); e != "" {
			emoji = &e
		}
	}

	user := v1User(r)
	var count int
	if err := h.Pool.QueryRow(r.Context(),
		"SELECT COUNT(*)::int FROM saved_foods WHERE user_id = $1", user.ID).Scan(&count); err != nil {
		apierr.Write(w, r, dbFail("count saved foods", err))
		return
	}
	if count >= MaxSavedFoods {
		apierr.Write(w, r, apierr.Conflict(
			fmt.Sprintf("You already have the maximum of %d saved foods.", MaxSavedFoods)))
		return
	}

	f, err := scanSavedFood(h.Pool.QueryRow(r.Context(), `
		INSERT INTO saved_foods (user_id, name, emoji, amount, protein_g, carbs_g, fat_g, fiber_g, sugar_g)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING `+savedFoodSelect,
		user.ID, name, emoji, in.Calories,
		macros["protein"], macros["carbs"], macros["fat"], macros["fiber"], macros["sugar"]))
	if err != nil {
		// saved_foods_user_name_idx is unique on (user_id, lower(name)) —
		// surface that as a 409 rather than a 500.
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			apierr.Write(w, r, apierr.Conflict("A saved food with that name already exists."))
			return
		}
		apierr.Write(w, r, dbFail("create saved food", err))
		return
	}

	h.broadcastFoods(user.ID)
	w.Header().Set("Location", fmt.Sprintf("/api/v1/saved-foods/%d", f.ID))
	writeV1(w, http.StatusCreated, f)
}

// v1SavedFoodPatch is the PATCH body. Optional fields distinguish absent from
// an explicit null; see Optional's doc comment.
type v1SavedFoodPatch struct {
	Name     *string          `json:"name"`
	Emoji    Optional[string] `json:"emoji"`
	Calories Optional[int]    `json:"calories"`
	ProteinG Optional[int]    `json:"protein_g"`
	CarbsG   Optional[int]    `json:"carbs_g"`
	FatG     Optional[int]    `json:"fat_g"`
	FiberG   Optional[int]    `json:"fiber_g"`
	SugarG   Optional[int]    `json:"sugar_g"`
}

// UpdateSavedFoodV1 handles PATCH /api/v1/saved-foods/{id}.
func (h *V1Handler) UpdateSavedFoodV1(w http.ResponseWriter, r *http.Request) {
	id, prob := pathID(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	var in v1SavedFoodPatch
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
		name := truncateUTF8(strings.TrimSpace(*in.Name), MaxSavedFoodName)
		if name == "" {
			apierr.Write(w, r, apierr.Unprocessable("A saved food needs a name.",
				apierr.InvalidParam{Name: "name", Reason: "must not be empty"}))
			return
		}
		set("name", name)
	}
	if in.Emoji.Set {
		if in.Emoji.Value == nil {
			set("emoji", nil)
		} else if e := truncateUTF8(strings.TrimSpace(*in.Emoji.Value), MaxSavedFoodEmoji); e == "" {
			set("emoji", nil)
		} else {
			set("emoji", e)
		}
	}
	if in.Calories.Set {
		if in.Calories.Value == nil {
			set("amount", nil)
		} else {
			if !entryCaloriesInRange(*in.Calories.Value) {
				apierr.Write(w, r, apierr.Unprocessable("The calorie value is out of range.",
					apierr.InvalidParam{
						Name:   "calories",
						Reason: fmt.Sprintf("must be between -%d and %d", MaxEntryCalories, MaxEntryCalories),
					}))
				return
			}
			set("amount", *in.Calories.Value)
		}
	}

	patchMacros := map[string]Optional[int]{
		"protein": in.ProteinG, "carbs": in.CarbsG, "fat": in.FatG,
		"fiber": in.FiberG, "sugar": in.SugarG,
	}
	var bad []apierr.InvalidParam
	for _, key := range service.MacroKeys {
		p := patchMacros[key]
		if !p.Set {
			continue
		}
		if p.Value == nil {
			set(key+"_g", nil)
			continue
		}
		if v := *p.Value; v < 0 || v > MaxEntryMacro {
			bad = append(bad, apierr.InvalidParam{
				Name:   key + "_g",
				Reason: fmt.Sprintf("must be between 0 and %d", MaxEntryMacro),
			})
			continue
		}
		set(key+"_g", *p.Value)
	}
	if bad != nil {
		apierr.Write(w, r, apierr.Unprocessable("One or more macro values are out of range.", bad...))
		return
	}
	if len(sets) == 0 {
		apierr.Write(w, r, apierr.BadRequest("The request body contained no updatable fields."))
		return
	}
	sets = append(sets, "updated_at = NOW()")

	user := v1User(r)
	args = append(args, id, user.ID)
	f, err := scanSavedFood(h.Pool.QueryRow(r.Context(), fmt.Sprintf(
		"UPDATE saved_foods SET %s WHERE id = $%d AND user_id = $%d RETURNING %s",
		strings.Join(sets, ", "), len(args)-1, len(args), savedFoodSelect), args...))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			apierr.Write(w, r, apierr.NotFound("No saved food with that id."))
			return
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			apierr.Write(w, r, apierr.Conflict("A saved food with that name already exists."))
			return
		}
		apierr.Write(w, r, dbFail("update saved food", err))
		return
	}

	h.broadcastFoods(user.ID)
	writeV1(w, http.StatusOK, f)
}

// DeleteSavedFoodV1 handles DELETE /api/v1/saved-foods/{id}.
func (h *V1Handler) DeleteSavedFoodV1(w http.ResponseWriter, r *http.Request) {
	id, prob := pathID(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	user := v1User(r)
	tag, err := h.Pool.Exec(r.Context(),
		"DELETE FROM saved_foods WHERE id = $1 AND user_id = $2", id, user.ID)
	if err != nil {
		apierr.Write(w, r, dbFail("delete saved food", err))
		return
	}
	if tag.RowsAffected() == 0 {
		apierr.Write(w, r, apierr.NotFound("No saved food with that id."))
		return
	}
	h.broadcastFoods(user.ID)
	noContent(w)
}

type v1TrackInput struct {
	Date     *string `json:"date"`
	Quantity *int    `json:"quantity"`
}

// TrackSavedFoodV1 handles POST /api/v1/saved-foods/{id}/track: turn a saved
// food into a calorie entry.
//
// It returns the created entry, not the food, because that is the thing the
// caller now needs an id for. Gated on entries:write — see the route table.
func (h *V1Handler) TrackSavedFoodV1(w http.ResponseWriter, r *http.Request) {
	id, prob := pathID(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	var in v1TrackInput
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
	qty := 1
	if in.Quantity != nil {
		if *in.Quantity < 1 || *in.Quantity > 99 {
			apierr.Write(w, r, apierr.Unprocessable("The quantity is out of range.",
				apierr.InvalidParam{Name: "quantity", Reason: "must be between 1 and 99"}))
			return
		}
		qty = *in.Quantity
	}

	user := v1User(r)
	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		apierr.Write(w, r, dbFail("begin track", err))
		return
	}
	defer tx.Rollback(r.Context())

	var name string
	var emoji *string
	var amount, protein, carbs, fat, fiber, sugar *int
	if err := tx.QueryRow(r.Context(),
		`SELECT name, emoji, amount, protein_g, carbs_g, fat_g, fiber_g, sugar_g
		 FROM saved_foods WHERE id = $1 AND user_id = $2`, id, user.ID,
	).Scan(&name, &emoji, &amount, &protein, &carbs, &fat, &fiber, &sugar); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			apierr.Write(w, r, apierr.NotFound("No saved food with that id."))
			return
		}
		apierr.Write(w, r, dbFail("load saved food", err))
		return
	}

	// Reuse the app's own multiplication + clamping so an API-tracked food
	// lands identically to a UI-tracked one.
	te, qty, ok := buildTrackedEntry(name, emoji, amount, protein, carbs, fat, fiber, sugar, qty)
	if !ok {
		apierr.Write(w, r, apierr.Unprocessable(
			"That quantity would push the entry past the per-entry calorie or macro limits.",
			apierr.InvalidParam{Name: "quantity", Reason: "result exceeds entry limits"}))
		return
	}

	e, err := scanEntry(tx.QueryRow(r.Context(), `
		INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name, protein_g, carbs_g, fat_g, fiber_g, sugar_g)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING `+entrySelect,
		user.ID, date, te.amount, nilString(te.name),
		te.protein, te.carbs, te.fat, te.fiber, te.sugar), v1Tz(r))
	if err != nil {
		apierr.Write(w, r, dbFail("track saved food", err))
		return
	}

	if _, err := tx.Exec(r.Context(),
		"UPDATE saved_foods SET use_count = use_count + $3, last_used_at = NOW() WHERE id = $1 AND user_id = $2",
		id, user.ID, qty); err != nil {
		apierr.Write(w, r, dbFail("bump saved food usage", err))
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		apierr.Write(w, r, dbFail("commit track", err))
		return
	}

	h.broadcastEntries(user.ID)
	h.broadcastFoods(user.ID)
	w.Header().Set("Location", fmt.Sprintf("/api/v1/entries/%d", e.ID))
	writeV1(w, http.StatusCreated, e)
}

func (h *V1Handler) broadcastFoods(userID int) {
	if h.Broker != nil {
		h.Broker.BroadcastSavedFoodChange(userID)
	}
}
