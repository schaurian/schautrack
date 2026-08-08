package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"schautrack/internal/apierr"
	"schautrack/internal/service"
)

// --- /me ------------------------------------------------------------------

// v1Me describes the authenticated principal: who the token belongs to, what
// it may do, and the account settings a client needs in order to interpret the
// other endpoints correctly.
//
// Timezone and weight_unit are here because they are not decoration — without
// them a client cannot tell what "today" means for this user or what unit a
// weight reading is in.
type v1Me struct {
	User struct {
		ID         int     `json:"id"`
		Email      string  `json:"email"`
		Timezone   string  `json:"timezone"`
		WeightUnit string  `json:"weight_unit"`
		DailyGoal  *int    `json:"daily_goal"`
		Language   *string `json:"language"`
	} `json:"user"`
	Token struct {
		ID        int        `json:"id"`
		Name      string     `json:"name"`
		Prefix    string     `json:"prefix"`
		Scopes    []string   `json:"scopes"`
		ExpiresAt *time.Time `json:"expires_at"`
	} `json:"token"`
	Server struct {
		Version string `json:"version"`
		Today   string `json:"today"`

		// Features reports which OPTIONAL endpoints this deployment actually
		// serves. Distinct from the account-level `features` below, and kept
		// under `server` for exactly that reason: one is what the user turned
		// on, the other is how the operator configured the instance, and
		// merging them would make a client unable to tell "you disabled this"
		// from "this server does not offer it".
		Features v1ServerFeatures `json:"features"`
	} `json:"server"`
	Features v1Features `json:"features"`
}

// v1ServerFeatures reports the endpoints that exist in the route table and the
// OpenAPI document unconditionally but answer 404 feature-disabled depending on
// how the server is configured (#392).
//
// Without this, discovering that an instance has no AI provider meant sending a
// photo and reading the 404 — and a client cannot tell that apart from a
// genuine not-found without parsing the problem `type`. Both fields are always
// present so a client never has to distinguish false from absent.
type v1ServerFeatures struct {
	// Barcode is true when BarcodeV1 is wired, i.e. GET /barcode/{code} will
	// attempt a lookup rather than answering feature-disabled.
	Barcode bool `json:"barcode"`

	// AIEstimate is true when an AI provider is configured. The account's own
	// daily cap still applies on top — this only says the endpoint is live.
	AIEstimate bool `json:"ai_estimate"`
}

// v1Features reports the per-account opt-ins that change how the rest of the
// API behaves. Without them the only way to discover the account's shape is to
// send a write and read the rejection: notes answer 409 when the feature is
// off, and PATCH /entries/{id} answers 422 for `calories` when auto-calc is on.
//
// Read-only here, deliberately. Turning these on and off belongs to the app's
// settings surface, which is session-authed and, for some of it, step-up gated;
// PATCH /me stays limited to the settings that describe how to interpret data
// (goal, timezone, unit, language) rather than which features exist. See #344.
//
// Every field is a plain bool and always present: a client checking
// `features.notes` must never have to distinguish "off" from "absent".
type v1Features struct {
	// BodyFat mirrors users.body_fat_enabled. Off means a stored reading is
	// not shown in the app, so a client writing one is writing into a column
	// the user never sees.
	BodyFat bool `json:"body_fat"`

	// Todos mirrors users.todos_enabled. The v1 todo endpoints do not gate on
	// it — a todo written while it is off is stored and returned by the API
	// but absent from the UI.
	Todos bool `json:"todos"`

	// Notes mirrors users.notes_enabled. This one IS gated:
	// requireNotesEnabledFor turns GET/PUT /notes/{date} into a 409 when it is
	// off, which is precisely what a client cannot otherwise predict.
	Notes bool `json:"notes"`

	// Macros is DERIVED, not stored: users.macros_enabled is a JSONB object of
	// per-macro toggles plus auto_calc_calories, and there is no single boolean
	// to report. True when at least one of protein/carbs/fat/fiber/sugar is on,
	// i.e. when the app shows any macro at all.
	Macros bool `json:"macros"`

	// AutoCalcCalories is the auto_calc_calories key of that same object. It is
	// the one flag with a hard, observable API consequence: with it on, POST
	// /entries computes `calories` from the macros and ignores what was sent,
	// and PATCH /entries/{id} rejects `calories` outright with a 422.
	AutoCalcCalories bool `json:"auto_calc_calories"`
}

// Me handles GET /api/v1/me. It requires a valid token but no scope: it is how
// a client discovers which scopes it holds, which it must be able to do before
// it knows whether any other call would succeed.
func (h *V1Handler) Me(w http.ResponseWriter, r *http.Request) {
	writeV1(w, http.StatusOK, h.buildMe(r, v1User(r)))
}

// --- Notes ----------------------------------------------------------------

// v1Note is one day's note.
type v1Note struct {
	Date      string     `json:"date"`
	Content   string     `json:"content"`
	UpdatedAt *time.Time `json:"updated_at"`
}

// maxNoteLen bounds a note body.
const maxNoteLen = 10000

// GetNoteV1 handles GET /api/v1/notes/{date}.
//
// A date with no note returns 200 with empty content, not 404: "no note today"
// is a normal state of an existing day, not a missing resource, and making
// callers branch on 404 for the common case would be hostile.
func (h *V1Handler) GetNoteV1(w http.ResponseWriter, r *http.Request) {
	date, prob := pathDate(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	tgt, prob := h.resolveTarget(r, service.ShareNotes)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	if prob := h.requireNotesEnabledFor(r, tgt.User.ID); prob != nil {
		apierr.Write(w, r, prob)
		return
	}

	out := v1Note{Date: date}
	err := h.Pool.QueryRow(r.Context(),
		"SELECT content, updated_at FROM daily_notes WHERE user_id = $1 AND note_date = $2",
		tgt.User.ID, date).Scan(&out.Content, &out.UpdatedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		apierr.Write(w, r, dbFail("get note", err))
		return
	}
	writeV1(w, http.StatusOK, out)
}

type v1NoteInput struct {
	Content string `json:"content"`
}

// PutNoteV1 handles PUT /api/v1/notes/{date} — an idempotent whole-content
// replace. Writing an empty string deletes the note.
func (h *V1Handler) PutNoteV1(w http.ResponseWriter, r *http.Request) {
	date, prob := pathDate(r)
	if prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	if prob := h.requireNotesEnabled(r); prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	var in v1NoteInput
	if prob := decodeV1(w, r, &in); prob != nil {
		apierr.Write(w, r, prob)
		return
	}
	if len(in.Content) > maxNoteLen {
		apierr.Write(w, r, apierr.Unprocessable("The note is too long.",
			apierr.InvalidParam{Name: "content", Reason: "must be at most 10000 characters"}))
		return
	}

	user := v1User(r)
	content := strings.TrimSpace(in.Content)
	if content == "" {
		if _, err := h.Pool.Exec(r.Context(),
			"DELETE FROM daily_notes WHERE user_id = $1 AND note_date = $2", user.ID, date); err != nil {
			apierr.Write(w, r, dbFail("delete note", err))
			return
		}
		h.broadcastEntries(user.ID)
		writeV1(w, http.StatusOK, v1Note{Date: date})
		return
	}

	out := v1Note{Date: date}
	if err := h.Pool.QueryRow(r.Context(), `
		INSERT INTO daily_notes (user_id, note_date, content) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, note_date)
			DO UPDATE SET content = EXCLUDED.content, updated_at = NOW()
		RETURNING content, updated_at`, user.ID, date, content,
	).Scan(&out.Content, &out.UpdatedAt); err != nil {
		apierr.Write(w, r, dbFail("save note", err))
		return
	}

	h.broadcastEntries(user.ID)
	writeV1(w, http.StatusOK, out)
}

// requireNotesEnabled rejects note access when the user has the feature off.
//
// 409 rather than 404: the endpoint exists and the token is allowed to use it;
// the account just has not turned the feature on, and saying so is what lets
// the caller fix it.
func (h *V1Handler) requireNotesEnabled(r *http.Request) *apierr.Problem {
	return h.requireNotesEnabledFor(r, v1User(r).ID)
}

// requireNotesEnabledFor checks the flag on a specific account, so a read of a
// linked account's notes reports THEIR setting rather than the caller's.
func (h *V1Handler) requireNotesEnabledFor(r *http.Request, userID int) *apierr.Problem {
	var enabled bool
	if err := h.Pool.QueryRow(r.Context(),
		"SELECT notes_enabled FROM users WHERE id = $1", userID).Scan(&enabled); err != nil {
		return dbFail("check notes enabled", err)
	}
	if !enabled {
		return apierr.Conflict("Daily notes are not enabled for this account. Enable them in Settings first.")
	}
	return nil
}

// --- Plan -----------------------------------------------------------------

// GetPlanV1 handles GET /api/v1/plan.
//
// The plan is a computed projection — goal, budget, curve, trend — assembled by
// service.AssemblePlan from body metrics and weight history. It delegates to
// PlanHandler.buildPlanInputs so the API and the UI cannot drift into computing
// two different plans from the same data.
//
// Read-only on purpose. Setting a weight goal is a considered decision with
// real health implications, so it stays in the UI where the app can show what
// the numbers mean; scripts read the plan, they do not silently rewrite it.
//
// One deliberate difference from the UI's GET /api/plan: that endpoint flips a
// reached goal to "achieved" as a side effect. This one does not. A `plan:read`
// token must not mutate state — the response still reports goalReachedNow
// truthfully, and the app performs the transition on its next load.
func (h *V1Handler) GetPlanV1(w http.ResponseWriter, r *http.Request) {
	ph := &PlanHandler{Pool: h.Pool, Broker: h.Broker}
	inputs, goal, unit, err := ph.buildPlanInputs(r, v1User(r))
	if err != nil {
		apierr.Write(w, r, dbFail("build plan inputs", err))
		return
	}

	resp := service.AssemblePlan(inputs)
	// AssemblePlan works in kg; echo the goal back in the user's own unit and
	// convert the rest of the weight-valued fields, exactly as the UI does.
	resp.Goal = goal
	service.ConvertPlanResponseToDisplayUnit(&resp, unit)

	writeV1(w, http.StatusOK, resp)
}
