package handler

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"schautrack/internal/apierr"
	"schautrack/internal/service"
)

// v1Weight is the public representation of a weight entry.
//
// Weights are stored in whatever unit the user configured — the app never
// converts — so the unit travels with every reading. A client that assumed
// kilograms would silently mis-plot a pounds account.
type v1Weight struct {
	Date      string    `json:"date"`
	Weight    float64   `json:"weight"`
	Unit      string    `json:"unit"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (h *V1Handler) weightUnit(r *http.Request) string {
	if u := v1User(r).WeightUnit; u != "" {
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

	user := v1User(r)
	where := []string{"user_id = $1"}
	args := []any{user.ID}
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
		`SELECT entry_date, weight, created_at, updated_at FROM weight_entries
		 WHERE %s ORDER BY entry_date DESC LIMIT $%d`,
		strings.Join(where, " AND "), len(args)), args...)
	if err != nil {
		apierr.Write(w, r, dbFail("list weight", err))
		return
	}
	defer rows.Close()

	unit := h.weightUnit(r)
	out := []v1Weight{}
	for rows.Next() {
		e := v1Weight{Unit: unit}
		if err := rows.Scan(&e.Date, &e.Weight, &e.CreatedAt, &e.UpdatedAt); err != nil {
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
func (h *V1Handler) GetWeightV1(w http.ResponseWriter, r *http.Request) {
	date, prob := pathDate(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	entry, err := service.GetWeightEntry(r.Context(), h.Pool, v1User(r).ID, date)
	if err != nil {
		apierr.Write(w, r, dbFail("get weight", err))
		return
	}
	if entry == nil {
		apierr.Write(w, r, apierr.NotFound("No weight recorded for that date."))
		return
	}
	writeV1(w, http.StatusOK, v1Weight{
		Date: entry.Date, Weight: entry.Weight, Unit: h.weightUnit(r),
		CreatedAt: entry.CreatedAt, UpdatedAt: entry.UpdatedAt,
	})
}

type v1WeightInput struct {
	Weight float64 `json:"weight"`
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

	user := v1User(r)
	existing, err := service.GetWeightEntry(r.Context(), h.Pool, user.ID, date)
	if err != nil {
		apierr.Write(w, r, dbFail("check weight", err))
		return
	}

	// KeepBodyFat: v1 does not expose the optional body-fat reading yet, and a
	// weight-only writer (typically a smart-scale integration) must not erase
	// one recorded in the app for the same day.
	entry, err := service.UpsertWeightEntry(r.Context(), h.Pool, user.ID, date, parsed.Value, service.KeepBodyFat)
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
		Date: entry.Date, Weight: entry.Weight, Unit: h.weightUnit(r),
		CreatedAt: entry.CreatedAt, UpdatedAt: entry.UpdatedAt,
	})
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
