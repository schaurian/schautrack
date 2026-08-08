package handler

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"schautrack/internal/apierr"
	"schautrack/internal/model"
	"schautrack/internal/service"
)

// v1Weight is the public representation of a weight entry.
//
// Weights are stored in whatever unit the user configured — the app never
// converts — so the unit travels with every reading. A client that assumed
// kilograms would silently mis-plot a pounds account.
type v1Weight struct {
	Date   string  `json:"date"`
	Weight float64 `json:"weight"`
	// BodyFat is the optional percentage recorded with the reading. Always
	// present in the JSON, null when the day carries no measurement — a
	// composition scale reports weight and body fat together, and a client
	// mirroring the app's data must be able to tell "not measured" apart from
	// "field not returned".
	BodyFat   *float64  `json:"body_fat"`
	Unit      string    `json:"unit"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// weightUnit is the caller's own unit. Write endpoints are self-only, so they
// use this; reads go through target.weightUnit, which reports the unit of
// whoever's readings are actually being returned.
func (h *V1Handler) weightUnit(r *http.Request) string {
	if u := v1User(r).WeightUnit; u != "" {
		return u
	}
	return "kg"
}

// weightUnit returns the unit a target's readings are stored in. A linked
// account's readings are in THEIR unit — the app never converts, so reporting
// the caller's unit would mislabel every number.
func (t target) weightUnit() string {
	if u := t.User.WeightUnit; u != "" {
		return u
	}
	return "kg"
}

// ListWeight handles GET /api/v1/weight, optionally bounded by from/to.
//
// Weight is the one collection here that grows without bound — todos cap at 20
// and saved foods at 200, but weight accrues a row per day forever. It is
// therefore cursor-paginated like entries: without one, a decade of readings
// (~3650 rows) simply cannot be enumerated past the 200-row page cap except by
// hand-chunking date ranges.
func (h *V1Handler) ListWeight(w http.ResponseWriter, r *http.Request) {
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

	tgt, prob := h.resolveTarget(r, service.ShareWeight)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	where := []string{"user_id = $1"}
	args := []any{tgt.User.ID}
	if from != "" {
		args = append(args, from)
		where = append(where, fmt.Sprintf("entry_date >= $%d", len(args)))
	}
	if to != "" {
		args = append(args, to)
		where = append(where, fmt.Sprintf("entry_date <= $%d", len(args)))
	}
	if cur != nil {
		// Strictly older than the cursor row. One row per user per day means
		// the date alone is a total order, so no tiebreaker column is needed.
		args = append(args, cur.Date)
		where = append(where, fmt.Sprintf("entry_date < $%d::date", len(args)))
	}
	// One row beyond the page reveals whether another page exists without a
	// second COUNT query.
	args = append(args, limit+1)

	rows, err := h.Pool.Query(r.Context(), fmt.Sprintf(
		`SELECT entry_date, weight, body_fat, created_at, updated_at FROM weight_entries
		 WHERE %s ORDER BY entry_date DESC LIMIT $%d`,
		strings.Join(where, " AND "), len(args)), args...)
	if err != nil {
		apierr.Write(w, r, dbFail("list weight", err))
		return
	}
	defer rows.Close()

	// A linked account's readings are in THEIR unit, not the caller's.
	unit := tgt.weightUnit()
	out := []v1Weight{}
	for rows.Next() {
		e := v1Weight{Unit: unit}
		if err := rows.Scan(&e.Date, &e.Weight, &e.BodyFat, &e.CreatedAt, &e.UpdatedAt); err != nil {
			apierr.Write(w, r, dbFail("scan weight", err))
			return
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		apierr.Write(w, r, dbFail("iterate weight", err))
		return
	}

	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	page := v1List[v1Weight]{Data: out, HasMore: &hasMore}
	if hasMore {
		// ID 0: the cursor encoding carries one, but weight has no surrogate
		// key to put there and the date is already a total order.
		next := encodeCursor(cursor{Date: out[len(out)-1].Date, ID: 1})
		page.NextCursor = &next
	}
	writeV1(w, http.StatusOK, page)
}

// GetWeightV1 handles GET /api/v1/weight/{date}.
//
// It honours ?user= so a date picked out of a linked account's GET /weight page
// can actually be fetched. Without it the list advertises dates this endpoint
// then reports as having no reading, which is a lie about someone else's data
// rather than a permission error.
func (h *V1Handler) GetWeightV1(w http.ResponseWriter, r *http.Request) {
	date, prob := pathDate(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	tgt, prob := h.resolveTarget(r, service.ShareWeight)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	entry, err := service.GetWeightEntry(r.Context(), h.Pool, tgt.User.ID, date)
	if err != nil {
		apierr.Write(w, r, dbFail("get weight", err))
		return
	}
	if entry == nil {
		apierr.Write(w, r, apierr.NotFound("No weight recorded for that date."))
		return
	}
	writeV1(w, http.StatusOK, v1Weight{
		Date: entry.Date, Weight: entry.Weight, BodyFat: entry.BodyFat,
		// The target's unit, not the caller's: a linked reading must be
		// reported in the unit it was recorded in.
		Unit:      tgt.weightUnit(),
		CreatedAt: entry.CreatedAt, UpdatedAt: entry.UpdatedAt,
	})
}

type v1WeightInput struct {
	Weight float64 `json:"weight"`

	// BodyFat is three-state, which is the whole reason it is Optional and not
	// a *float64: absent leaves any stored reading alone, null clears it, a
	// number sets it. Absent-means-keep is what lets a weight-only scale
	// integration retry without erasing a measurement taken in the app.
	BodyFat Optional[float64] `json:"body_fat"`
}

// bodyFatUpdate maps the Optional body_fat of a v1 request onto the three
// states of a service.BodyFatUpdate. It is the same mapping the session route's
// parseBodyFatUpdate performs, expressed against Optional rather than a decoded
// map[string]any — the semantics are deliberately identical, so a reading
// written through the API and one written in the app behave the same way.
//
// ok is false only when a value was supplied but is unusable, so the caller can
// answer 422 rather than silently dropping it.
func bodyFatUpdate(in Optional[float64]) (service.BodyFatUpdate, bool) {
	if !in.Set {
		return service.KeepBodyFat, true
	}
	if in.Value == nil {
		return service.BodyFatUpdate{Set: true}, true
	}
	// service.ParseBodyFat takes a string because the UI and the import path
	// both hand it one; reusing it is what keeps the API's accepted range
	// identical to the app's. Formatting at fixed precision rather than %v
	// keeps a float that Go would render as 22.499999999999996 within the
	// parser's 12-byte input cap — the parser rounds to one decimal anyway, so
	// nothing meaningful is lost, and a client computing a percentage is not
	// rejected over spurious digits.
	pct, ok := service.ParseBodyFat(strconv.FormatFloat(*in.Value, 'f', 4, 64))
	if !ok {
		return service.BodyFatUpdate{}, false
	}
	return service.BodyFatUpdate{Set: true, Value: &pct}, true
}

// PutWeightV1 handles PUT /api/v1/weight/{date} — an upsert.
//
// PUT rather than POST because the date in the URL fully identifies the
// resource and the operation is idempotent: a scale integration that retries
// after a timeout must not create a second reading. It returns 200 on replace
// and 201 on first write so a caller can tell which happened.
func (h *V1Handler) PutWeightV1(w http.ResponseWriter, r *http.Request) {
	date, prob := pathDate(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	var in v1WeightInput
	if prob := decodeV1(w, r, &in); prob != nil {
		apierr.Write(w, r, prob)
		return
	}

	// Reuse the app's own parser so the API accepts exactly the values the UI
	// does, including its rounding to two decimals and its 0 < w <= 1500 bound.
	parsed := service.ParseWeight(fmt.Sprintf("%v", in.Weight))
	if !parsed.Ok {
		apierr.Write(w, r, apierr.Unprocessable("The weight value is not usable.",
			apierr.InvalidParam{Name: "weight", Reason: "must be a number greater than 0 and at most 1500"}))
		return
	}

	// Validated before anything touches the database, so an out-of-range
	// percentage is a 422 problem+json and never reaches the CHECK constraint
	// that would surface it as a 500.
	bodyFat, ok := bodyFatUpdate(in.BodyFat)
	if !ok {
		apierr.Write(w, r, apierr.Unprocessable("The body fat value is not usable.",
			apierr.InvalidParam{
				Name:   "body_fat",
				Reason: fmt.Sprintf("must be a number greater than 0 and at most %g, or null to clear it", service.MaxBodyFatPct),
			}))
		return
	}

	user := v1User(r)
	existing, err := service.GetWeightEntry(r.Context(), h.Pool, user.ID, date)
	if err != nil {
		apierr.Write(w, r, dbFail("check weight", err))
		return
	}

	// An omitted body_fat still means KeepBodyFat: a weight-only writer
	// (typically a smart-scale integration) must not erase a reading recorded
	// in the app for the same day.
	entry, err := h.upsertWeight(r.Context(), user, date, parsed.Value, bodyFat)
	if err != nil {
		apierr.Write(w, r, dbFail("upsert weight", err))
		return
	}

	status := http.StatusOK
	if existing == nil {
		status = http.StatusCreated
		w.Header().Set("Location", "/api/v1/weight/"+date)
	}
	h.broadcastEntries(user.ID)
	writeV1(w, status, v1Weight{
		Date: entry.Date, Weight: entry.Weight, BodyFat: entry.BodyFat,
		Unit:      h.weightUnit(r),
		CreatedAt: entry.CreatedAt, UpdatedAt: entry.UpdatedAt,
	})
}

// upsertWeight writes the reading and, when the request actually carries a body
// fat for an account that has never switched the field on, turns the opt-in on
// in the same transaction.
//
// The flip mirrors what import already does, for the same reason: without it a
// reading written by a composition scale is stored, feeds the planner's
// Katch-McArdle BMR, and is nonetheless invisible and uneditable in the app
// until the user happens to find the setting. `users.body_fat_enabled` governs
// only whether the UI offers the field (see ToggleBodyFatEnabled) — it is not
// an authorization gate — so turning it on grants nothing and destroys nothing.
//
// It is one-way. Clearing a reading with `null` must not switch the field back
// off: other days may still carry measurements, and hiding the input as a side
// effect of clearing one day would be a surprise the caller never asked for.
func (h *V1Handler) upsertWeight(ctx context.Context, user *model.User, date string, weight float64, bodyFat service.BodyFatUpdate) (*service.WeightResult, error) {
	if bodyFat.Value == nil || user.BodyFatEnabled {
		return service.UpsertWeightEntry(ctx, h.Pool, user.ID, date, weight, bodyFat)
	}

	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	entry, err := service.UpsertWeightEntry(ctx, tx, user.ID, date, weight, bodyFat)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, "UPDATE users SET body_fat_enabled = TRUE WHERE id = $1", user.ID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return entry, nil
}

// DeleteWeightV1 handles DELETE /api/v1/weight/{date}.
func (h *V1Handler) DeleteWeightV1(w http.ResponseWriter, r *http.Request) {
	date, prob := pathDate(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	user := v1User(r)
	tag, err := h.Pool.Exec(r.Context(),
		"DELETE FROM weight_entries WHERE user_id = $1 AND entry_date = $2", user.ID, date)
	if err != nil {
		apierr.Write(w, r, dbFail("delete weight", err))
		return
	}
	if tag.RowsAffected() == 0 {
		apierr.Write(w, r, apierr.NotFound("No weight recorded for that date."))
		return
	}
	h.broadcastEntries(user.ID)
	noContent(w)
}
