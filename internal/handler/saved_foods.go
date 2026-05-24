package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/sse"
)

const (
	MaxSavedFoods     = 200
	MaxSavedFoodName  = 80
	MaxSavedFoodEmoji = 16
)

type SavedFoodsHandler struct {
	Pool   *pgxpool.Pool
	Broker *sse.Broker
}

type savedFoodView struct {
	ID         int             `json:"id"`
	Name       string          `json:"name"`
	Emoji      *string         `json:"emoji"`
	Amount     *int            `json:"amount"`
	Macros     map[string]*int `json:"macros"`
	UseCount   int             `json:"use_count"`
	LastUsedAt *time.Time      `json:"last_used_at"`
}

func toSavedFoodView(id int, name string, emoji *string, amount, protein, carbs, fat, fiber, sugar *int,
	useCount int, lastUsedAt *time.Time) savedFoodView {
	return savedFoodView{
		ID: id, Name: name, Emoji: emoji, Amount: amount,
		Macros: map[string]*int{
			"protein": protein, "carbs": carbs, "fat": fat, "fiber": fiber, "sugar": sugar,
		},
		UseCount: useCount, LastUsedAt: lastUsedAt,
	}
}

// List handles GET /api/saved-foods. Returns the caller's own foods only,
// ranked by use_count then last_used_at.
func (h *SavedFoodsHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)

	rows, err := h.Pool.Query(r.Context(), `
		SELECT id, name, emoji, amount, protein_g, carbs_g, fat_g, fiber_g, sugar_g,
		       use_count, last_used_at
		FROM saved_foods
		WHERE user_id = $1
		ORDER BY use_count DESC, last_used_at DESC NULLS LAST, id DESC`,
		user.ID)
	if err != nil {
		slog.Error("saved_foods list", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to load saved foods")
		return
	}
	defer rows.Close()

	out := []savedFoodView{}
	for rows.Next() {
		var id, useCount int
		var name string
		var emoji *string
		var amount, protein, carbs, fat, fiber, sugar *int
		var lastUsedAt *time.Time
		if err := rows.Scan(&id, &name, &emoji, &amount, &protein, &carbs, &fat, &fiber, &sugar,
			&useCount, &lastUsedAt); err != nil {
			continue
		}
		out = append(out, toSavedFoodView(id, name, emoji, amount, protein, carbs, fat, fiber, sugar,
			useCount, lastUsedAt))
	}

	JSON(w, http.StatusOK, map[string]any{"ok": true, "savedFoods": out})
}

// parseSavedFoodPayload pulls name, emoji, amount, and macro values from a
// JSON body. Returns the parsed values or an error message + status code.
// Used by both Create and Update; pass forCreate=true to require a non-empty name.
type savedFoodInput struct {
	hasName    bool
	name       string
	hasEmoji   bool
	emoji      *string
	hasAmount  bool
	amount     *int
	macros     map[string]*int // only keys present in body are populated
}

func parseSavedFoodPayload(body map[string]any, forCreate bool) (*savedFoodInput, int, string) {
	out := &savedFoodInput{macros: map[string]*int{}}

	if v, ok := body["name"]; ok {
		out.hasName = true
		out.name = strings.TrimSpace(fmt.Sprintf("%v", v))
		if len(out.name) > MaxSavedFoodName {
			out.name = out.name[:MaxSavedFoodName]
		}
		if out.name == "" {
			return nil, http.StatusBadRequest, "Name is required"
		}
	} else if forCreate {
		return nil, http.StatusBadRequest, "Name is required"
	}

	if v, ok := body["emoji"]; ok {
		out.hasEmoji = true
		raw := strings.TrimSpace(fmt.Sprintf("%v", v))
		if raw == "" || raw == "<nil>" {
			out.emoji = nil
		} else {
			if len(raw) > MaxSavedFoodEmoji {
				raw = raw[:MaxSavedFoodEmoji]
			}
			out.emoji = &raw
		}
	}

	if v, ok := body["amount"]; ok && v != nil {
		out.hasAmount = true
		raw := strings.TrimSpace(fmt.Sprintf("%v", v))
		if raw == "" || raw == "<nil>" {
			out.amount = nil
		} else {
			parsed := service.ParseAmount(raw, MaxEntryCalories)
			if !parsed.Ok {
				return nil, http.StatusBadRequest, fmt.Sprintf("Calories must be between -%d and %d", MaxEntryCalories, MaxEntryCalories)
			}
			n := parsed.Value
			out.amount = &n
		}
	}

	for _, key := range service.MacroKeys {
		field := key + "_g"
		v, ok := body[field]
		if !ok {
			continue
		}
		if v == nil {
			out.macros[key] = nil
			continue
		}
		raw := strings.TrimSpace(fmt.Sprintf("%v", v))
		if raw == "" || raw == "<nil>" {
			out.macros[key] = nil
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > MaxEntryMacro {
			return nil, http.StatusBadRequest, fmt.Sprintf("Macro values must be between 0 and %d", MaxEntryMacro)
		}
		val := n
		out.macros[key] = &val
	}

	return out, 0, ""
}

func (h *SavedFoodsHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	input, status, msg := parseSavedFoodPayload(body, true)
	if status != 0 {
		ErrorJSON(w, status, msg)
		return
	}

	user := middleware.GetCurrentUser(r)

	var count int
	if err := h.Pool.QueryRow(r.Context(), "SELECT COUNT(*)::int FROM saved_foods WHERE user_id = $1", user.ID).Scan(&count); err != nil {
		slog.Error("saved_foods count", "error", err)
	}
	if count >= MaxSavedFoods {
		ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Maximum %d saved foods allowed", MaxSavedFoods))
		return
	}

	var id int
	var createdAt, updatedAt time.Time
	err := h.Pool.QueryRow(r.Context(), `
		INSERT INTO saved_foods (user_id, name, emoji, amount, protein_g, carbs_g, fat_g, fiber_g, sugar_g)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at`,
		user.ID, input.name, input.emoji, input.amount,
		input.macros["protein"], input.macros["carbs"], input.macros["fat"],
		input.macros["fiber"], input.macros["sugar"],
	).Scan(&id, &createdAt, &updatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			ErrorJSON(w, http.StatusConflict, "A saved food with that name already exists")
			return
		}
		slog.Error("saved_foods insert", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to save food")
		return
	}

	h.Broker.BroadcastSavedFoodChange(user.ID)
	JSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"savedFood": toSavedFoodView(id, input.name, input.emoji, input.amount,
			input.macros["protein"], input.macros["carbs"], input.macros["fat"],
			input.macros["fiber"], input.macros["sugar"],
			0, nil),
	})
}

func (h *SavedFoodsHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid id")
		return
	}

	var body map[string]any
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	input, status, msg := parseSavedFoodPayload(body, false)
	if status != 0 {
		ErrorJSON(w, status, msg)
		return
	}

	user := middleware.GetCurrentUser(r)

	var updates []string
	var values []any
	idx := 1

	if input.hasName {
		updates = append(updates, fmt.Sprintf("name = $%d", idx))
		values = append(values, input.name)
		idx++
	}
	if input.hasEmoji {
		updates = append(updates, fmt.Sprintf("emoji = $%d", idx))
		values = append(values, input.emoji)
		idx++
	}
	if input.hasAmount {
		updates = append(updates, fmt.Sprintf("amount = $%d", idx))
		values = append(values, input.amount)
		idx++
	}
	for _, key := range service.MacroKeys {
		if v, ok := input.macros[key]; ok || hasKey(body, key+"_g") {
			updates = append(updates, fmt.Sprintf("%s_g = $%d", key, idx))
			values = append(values, v)
			idx++
		}
	}
	if len(updates) == 0 {
		ErrorJSON(w, http.StatusBadRequest, "No updates provided")
		return
	}

	updates = append(updates, "updated_at = NOW()")

	query := fmt.Sprintf(`
		UPDATE saved_foods SET %s
		WHERE id = $%d AND user_id = $%d
		RETURNING id, name, emoji, amount, protein_g, carbs_g, fat_g, fiber_g, sugar_g, use_count, last_used_at`,
		strings.Join(updates, ", "), idx, idx+1)
	values = append(values, id, user.ID)

	var name string
	var emoji *string
	var amount, protein, carbs, fat, fiber, sugar *int
	var useCount int
	var lastUsedAt *time.Time
	err = h.Pool.QueryRow(r.Context(), query, values...).Scan(
		&id, &name, &emoji, &amount, &protein, &carbs, &fat, &fiber, &sugar,
		&useCount, &lastUsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			ErrorJSON(w, http.StatusNotFound, "Saved food not found")
			return
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			ErrorJSON(w, http.StatusConflict, "A saved food with that name already exists")
			return
		}
		slog.Error("saved_foods update", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to update saved food")
		return
	}

	h.Broker.BroadcastSavedFoodChange(user.ID)
	JSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"savedFood": toSavedFoodView(id, name, emoji, amount, protein, carbs, fat, fiber, sugar,
			useCount, lastUsedAt),
	})
}

func (h *SavedFoodsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid id")
		return
	}
	user := middleware.GetCurrentUser(r)
	tag, err := h.Pool.Exec(r.Context(), "DELETE FROM saved_foods WHERE id = $1 AND user_id = $2", id, user.ID)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to delete saved food")
		return
	}
	if tag.RowsAffected() == 0 {
		ErrorJSON(w, http.StatusNotFound, "Saved food not found")
		return
	}
	h.Broker.BroadcastSavedFoodChange(user.ID)
	OkJSON(w)
}

// Track handles POST /api/saved-foods/{id}/track. It transactionally inserts a
// calorie_entries row from the saved food's template values, bumps use_count,
// and sets last_used_at. Returns the created entry id so the dashboard can
// offer Undo (delete that specific entry).
func (h *SavedFoodsHandler) Track(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid id")
		return
	}

	var body struct {
		EntryDate string `json:"entry_date"`
	}
	ReadJSON(r, &body)

	user := middleware.GetCurrentUser(r)
	userTz := getUserTimezone(r, user)

	entryDate := strings.TrimSpace(body.EntryDate)
	if entryDate == "" {
		entryDate = service.FormatDateInTz(time.Now(), userTz)
	}
	if !dateRe.MatchString(entryDate) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid date")
		return
	}

	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to track entry")
		return
	}
	defer tx.Rollback(r.Context())

	var name string
	var emoji *string
	var amount, protein, carbs, fat, fiber, sugar *int
	err = tx.QueryRow(r.Context(), `
		SELECT name, emoji, amount, protein_g, carbs_g, fat_g, fiber_g, sugar_g
		FROM saved_foods
		WHERE id = $1 AND user_id = $2`,
		id, user.ID).Scan(&name, &emoji, &amount, &protein, &carbs, &fat, &fiber, &sugar)
	if err != nil {
		ErrorJSON(w, http.StatusNotFound, "Saved food not found")
		return
	}

	// Build entry name. Prefix with emoji if set.
	entryName := name
	if emoji != nil && *emoji != "" {
		entryName = *emoji + " " + name
	}
	if len(entryName) > 120 {
		entryName = entryName[:120]
	}

	entryAmount := 0
	if amount != nil {
		entryAmount = *amount
	}

	var entryID int
	var createdAt time.Time
	err = tx.QueryRow(r.Context(), `
		INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name, protein_g, carbs_g, fat_g, fiber_g, sugar_g)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at`,
		user.ID, entryDate, entryAmount, nilString(entryName),
		protein, carbs, fat, fiber, sugar,
	).Scan(&entryID, &createdAt)
	if err != nil {
		slog.Error("saved_foods track insert", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to track entry")
		return
	}

	if _, err := tx.Exec(r.Context(),
		"UPDATE saved_foods SET use_count = use_count + 1, last_used_at = NOW() WHERE id = $1 AND user_id = $2",
		id, user.ID); err != nil {
		slog.Error("saved_foods bump use_count", "error", err)
	}

	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to track entry")
		return
	}

	h.Broker.BroadcastEntryChange(user.ID)
	h.Broker.BroadcastSavedFoodChange(user.ID)

	mu := service.ParseMacroUser(user.MacrosEnabled, user.MacroGoals, user.DailyGoal, user.GoalThreshold)
	enabled := service.GetEnabledMacros(mu)
	macros := buildMacroMap(enabled, protein, carbs, fat, fiber, sugar)

	JSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"entry": map[string]any{
			"id": entryID, "date": entryDate, "amount": entryAmount,
			"time": service.FormatTimeInTz(createdAt, userTz),
			"name": entryName, "macros": macros,
		},
	})
}

// SaveFromEntry handles POST /api/entries/{id}/save-as-food — Phase 4 helper that
// turns an existing entry into a saved food. Useful from the EntryList row menu.
func (h *SavedFoodsHandler) SaveFromEntry(w http.ResponseWriter, r *http.Request) {
	entryID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid entry id")
		return
	}

	user := middleware.GetCurrentUser(r)

	var name *string
	var amount int
	var protein, carbs, fat, fiber, sugar *int
	err = h.Pool.QueryRow(r.Context(), `
		SELECT entry_name, amount, protein_g, carbs_g, fat_g, fiber_g, sugar_g
		FROM calorie_entries WHERE id = $1 AND user_id = $2`,
		entryID, user.ID).Scan(&name, &amount, &protein, &carbs, &fat, &fiber, &sugar)
	if err != nil {
		ErrorJSON(w, http.StatusNotFound, "Entry not found")
		return
	}
	if name == nil || strings.TrimSpace(*name) == "" {
		ErrorJSON(w, http.StatusBadRequest, "Entry has no name to save as a food")
		return
	}

	// Optional body { emoji? }
	var body struct {
		Emoji *string `json:"emoji"`
	}
	ReadJSON(r, &body)

	cleanName := strings.TrimSpace(*name)
	if len(cleanName) > MaxSavedFoodName {
		cleanName = cleanName[:MaxSavedFoodName]
	}

	var count int
	h.Pool.QueryRow(r.Context(), "SELECT COUNT(*)::int FROM saved_foods WHERE user_id = $1", user.ID).Scan(&count)
	if count >= MaxSavedFoods {
		ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Maximum %d saved foods allowed", MaxSavedFoods))
		return
	}

	var amountPtr *int
	if amount != 0 {
		a := amount
		amountPtr = &a
	}

	var newID int
	err = h.Pool.QueryRow(r.Context(), `
		INSERT INTO saved_foods (user_id, name, emoji, amount, protein_g, carbs_g, fat_g, fiber_g, sugar_g)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id`,
		user.ID, cleanName, body.Emoji, amountPtr,
		protein, carbs, fat, fiber, sugar,
	).Scan(&newID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			ErrorJSON(w, http.StatusConflict, "A saved food with that name already exists")
			return
		}
		slog.Error("saved_foods save-from-entry", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to save food")
		return
	}

	h.Broker.BroadcastSavedFoodChange(user.ID)
	JSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"savedFood": toSavedFoodView(newID, cleanName, body.Emoji, amountPtr,
			protein, carbs, fat, fiber, sugar, 0, nil),
	})
}

func hasKey(m map[string]any, k string) bool {
	_, ok := m[k]
	return ok
}

