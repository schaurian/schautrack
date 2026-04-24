package handler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/service"
	"schautrack/internal/sse"
)

// MealTemplatesHandler holds deps for meal-template routes.
type MealTemplatesHandler struct {
	Pool   *pgxpool.Pool
	Broker *sse.Broker
}

// templateItemBody is the wire format for an item in a create/update request.
type templateItemBody struct {
	EntryName *string `json:"entry_name"`
	Amount    int     `json:"amount"`
	ProteinG  *int    `json:"protein_g"`
	CarbsG    *int    `json:"carbs_g"`
	FatG      *int    `json:"fat_g"`
	FiberG    *int    `json:"fiber_g"`
	SugarG    *int    `json:"sugar_g"`
}

// templateWriteBody is the wire format for create/update.
type templateWriteBody struct {
	Name       string             `json:"name"`
	IsFavorite bool               `json:"is_favorite"`
	Items      []templateItemBody `json:"items"`
}

func itemBodyToInput(b templateItemBody) service.MealTemplateItemInput {
	in := service.MealTemplateItemInput{
		Amount: b.Amount,
		Macros: map[string]int{},
	}
	if b.EntryName != nil {
		in.EntryName = *b.EntryName
	}
	if b.ProteinG != nil {
		in.Macros["protein"] = *b.ProteinG
	}
	if b.CarbsG != nil {
		in.Macros["carbs"] = *b.CarbsG
	}
	if b.FatG != nil {
		in.Macros["fat"] = *b.FatG
	}
	if b.FiberG != nil {
		in.Macros["fiber"] = *b.FiberG
	}
	if b.SugarG != nil {
		in.Macros["sugar"] = *b.SugarG
	}
	return in
}

// List returns the current user's templates (with items).
// Optional query param: favorites=true restricts to starred templates.
func (h *MealTemplatesHandler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	favoritesOnly := r.URL.Query().Get("favorites") == "true"

	var query string
	args := []any{user.ID}
	if favoritesOnly {
		query = `SELECT id, name, is_favorite, sort_order, created_at, updated_at
		         FROM meal_templates WHERE user_id = $1 AND is_favorite = TRUE
		         ORDER BY sort_order, created_at DESC`
	} else {
		query = `SELECT id, name, is_favorite, sort_order, created_at, updated_at
		         FROM meal_templates WHERE user_id = $1
		         ORDER BY is_favorite DESC, sort_order, created_at DESC`
	}

	rows, err := h.Pool.Query(r.Context(), query, args...)
	if err != nil {
		slog.Error("failed to list meal templates", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to load templates")
		return
	}
	defer rows.Close()

	templates := []model.MealTemplate{}
	idByIdx := map[int]int{}
	for rows.Next() {
		var t model.MealTemplate
		if err := rows.Scan(&t.ID, &t.Name, &t.IsFavorite, &t.SortOrder, &t.CreatedAt, &t.UpdatedAt); err != nil {
			slog.Error("scan meal template", "error", err)
			continue
		}
		t.UserID = user.ID
		t.Items = []model.MealTemplateItem{}
		idByIdx[t.ID] = len(templates)
		templates = append(templates, t)
	}
	rows.Close()

	if len(templates) == 0 {
		JSON(w, http.StatusOK, map[string]any{"ok": true, "templates": templates})
		return
	}

	ids := make([]int, 0, len(templates))
	for _, t := range templates {
		ids = append(ids, t.ID)
	}

	itemRows, err := h.Pool.Query(r.Context(), `
		SELECT id, template_id, entry_name, amount, protein_g, carbs_g, fat_g, fiber_g, sugar_g, sort_order
		FROM meal_template_items WHERE template_id = ANY($1) ORDER BY template_id, sort_order, id`, ids)
	if err != nil {
		slog.Error("failed to load template items", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to load templates")
		return
	}
	defer itemRows.Close()
	for itemRows.Next() {
		var it model.MealTemplateItem
		if err := itemRows.Scan(&it.ID, &it.TemplateID, &it.EntryName, &it.Amount,
			&it.ProteinG, &it.CarbsG, &it.FatG, &it.FiberG, &it.SugarG, &it.SortOrder); err != nil {
			slog.Error("scan template item", "error", err)
			continue
		}
		if idx, ok := idByIdx[it.TemplateID]; ok {
			templates[idx].Items = append(templates[idx].Items, it)
		}
	}

	JSON(w, http.StatusOK, map[string]any{"ok": true, "templates": templates})
}

// Create handles POST /templates.
func (h *MealTemplatesHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body templateWriteBody
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	input := service.MealTemplateInput{
		Name:       body.Name,
		IsFavorite: body.IsFavorite,
		Items:      make([]service.MealTemplateItemInput, 0, len(body.Items)),
	}
	for _, it := range body.Items {
		input.Items = append(input.Items, itemBodyToInput(it))
	}
	cleaned, errMsg := service.ValidateMealTemplateInput(input)
	if errMsg != "" {
		ErrorJSON(w, http.StatusBadRequest, errMsg)
		return
	}

	user := middleware.GetCurrentUser(r)
	var count int
	if err := h.Pool.QueryRow(r.Context(), "SELECT COUNT(*)::int FROM meal_templates WHERE user_id = $1", user.ID).Scan(&count); err != nil {
		slog.Error("count meal templates", "error", err)
	}
	if count >= service.MaxMealTemplates {
		ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Maximum %d templates allowed", service.MaxMealTemplates))
		return
	}

	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to save template")
		return
	}
	defer tx.Rollback(r.Context())

	var id int
	err = tx.QueryRow(r.Context(),
		`INSERT INTO meal_templates (user_id, name, is_favorite, sort_order)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		user.ID, cleaned.Name, cleaned.IsFavorite, count,
	).Scan(&id)
	if err != nil {
		slog.Error("insert meal template", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to save template")
		return
	}

	if err := insertTemplateItems(r, tx, id, cleaned.Items); err != nil {
		slog.Error("insert meal template items", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to save template")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to save template")
		return
	}
	h.Broker.BroadcastTemplateChange(user.ID)
	OkJSON(w, map[string]any{"id": id})
}

// Update handles POST /templates/{id}/update. Replaces name/is_favorite and all items.
func (h *MealTemplatesHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid template id")
		return
	}
	var body templateWriteBody
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	input := service.MealTemplateInput{
		Name:       body.Name,
		IsFavorite: body.IsFavorite,
		Items:      make([]service.MealTemplateItemInput, 0, len(body.Items)),
	}
	for _, it := range body.Items {
		input.Items = append(input.Items, itemBodyToInput(it))
	}
	cleaned, errMsg := service.ValidateMealTemplateInput(input)
	if errMsg != "" {
		ErrorJSON(w, http.StatusBadRequest, errMsg)
		return
	}

	user := middleware.GetCurrentUser(r)

	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to update template")
		return
	}
	defer tx.Rollback(r.Context())

	tag, err := tx.Exec(r.Context(),
		`UPDATE meal_templates SET name = $1, is_favorite = $2, updated_at = NOW()
		 WHERE id = $3 AND user_id = $4`,
		cleaned.Name, cleaned.IsFavorite, id, user.ID,
	)
	if err != nil || tag.RowsAffected() == 0 {
		ErrorJSON(w, http.StatusNotFound, "Template not found")
		return
	}

	if _, err := tx.Exec(r.Context(), "DELETE FROM meal_template_items WHERE template_id = $1", id); err != nil {
		slog.Error("delete template items", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to update template")
		return
	}
	if err := insertTemplateItems(r, tx, id, cleaned.Items); err != nil {
		slog.Error("insert template items on update", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to update template")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to update template")
		return
	}
	h.Broker.BroadcastTemplateChange(user.ID)
	OkJSON(w)
}

// Delete handles POST /templates/{id}/delete.
func (h *MealTemplatesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid template id")
		return
	}
	user := middleware.GetCurrentUser(r)
	tag, err := h.Pool.Exec(r.Context(),
		"DELETE FROM meal_templates WHERE id = $1 AND user_id = $2", id, user.ID)
	if err != nil || tag.RowsAffected() == 0 {
		ErrorJSON(w, http.StatusNotFound, "Template not found")
		return
	}
	h.Broker.BroadcastTemplateChange(user.ID)
	OkJSON(w)
}

// ToggleFavorite handles POST /templates/{id}/favorite.
// Body: optional {"is_favorite": true|false}. If absent, toggles.
func (h *MealTemplatesHandler) ToggleFavorite(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid template id")
		return
	}
	user := middleware.GetCurrentUser(r)

	var body struct {
		IsFavorite *bool `json:"is_favorite"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	var newVal bool
	var query string
	var args []any
	if body.IsFavorite != nil {
		query = `UPDATE meal_templates SET is_favorite = $1, updated_at = NOW()
		         WHERE id = $2 AND user_id = $3 RETURNING is_favorite`
		args = []any{*body.IsFavorite, id, user.ID}
	} else {
		query = `UPDATE meal_templates SET is_favorite = NOT is_favorite, updated_at = NOW()
		         WHERE id = $1 AND user_id = $2 RETURNING is_favorite`
		args = []any{id, user.ID}
	}
	if err := h.Pool.QueryRow(r.Context(), query, args...).Scan(&newVal); err != nil {
		ErrorJSON(w, http.StatusNotFound, "Template not found")
		return
	}
	h.Broker.BroadcastTemplateChange(user.ID)
	JSON(w, http.StatusOK, map[string]any{"ok": true, "is_favorite": newVal})
}

// Apply handles POST /templates/{id}/apply?day=YYYY-MM-DD.
// Inserts the template's items into calorie_entries for the given day.
func (h *MealTemplatesHandler) Apply(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid template id")
		return
	}

	user := middleware.GetCurrentUser(r)
	userTz := getUserTimezone(r, user)
	day := strings.TrimSpace(r.URL.Query().Get("day"))
	if day == "" {
		day = service.FormatDateInTz(time.Now(), userTz)
	}
	if !dateRe.MatchString(day) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid day")
		return
	}

	// Load items.
	rows, err := h.Pool.Query(r.Context(), `
		SELECT mti.entry_name, mti.amount, mti.protein_g, mti.carbs_g, mti.fat_g, mti.fiber_g, mti.sugar_g
		FROM meal_template_items mti
		JOIN meal_templates mt ON mt.id = mti.template_id
		WHERE mt.id = $1 AND mt.user_id = $2
		ORDER BY mti.sort_order, mti.id`, id, user.ID)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to apply template")
		return
	}
	defer rows.Close()

	type item struct {
		EntryName *string
		Amount    int
		ProteinG  *int
		CarbsG    *int
		FatG      *int
		FiberG    *int
		SugarG    *int
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.EntryName, &it.Amount, &it.ProteinG, &it.CarbsG, &it.FatG, &it.FiberG, &it.SugarG); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Failed to apply template")
			return
		}
		items = append(items, it)
	}
	rows.Close()
	if len(items) == 0 {
		// Either the template doesn't exist for this user, or it's empty (shouldn't happen per validation).
		ErrorJSON(w, http.StatusNotFound, "Template not found")
		return
	}

	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to apply template")
		return
	}
	defer tx.Rollback(r.Context())

	inserted := 0
	for _, it := range items {
		_, err := tx.Exec(r.Context(), `
			INSERT INTO calorie_entries (user_id, entry_date, amount, entry_name, protein_g, carbs_g, fat_g, fiber_g, sugar_g)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			user.ID, day, it.Amount, it.EntryName, it.ProteinG, it.CarbsG, it.FatG, it.FiberG, it.SugarG)
		if err != nil {
			slog.Error("insert applied entry", "error", err)
			ErrorJSON(w, http.StatusInternalServerError, "Failed to apply template")
			return
		}
		inserted++
	}

	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to apply template")
		return
	}
	h.Broker.BroadcastEntryChange(user.ID)
	OkJSON(w, map[string]any{"count": inserted, "day": day})
}

// insertTemplateItems writes the ordered list of items for a template inside an open tx.
func insertTemplateItems(r *http.Request, tx pgx.Tx, templateID int, items []service.MealTemplateItemInput) error {
	for idx, it := range items {
		var entryName *string
		if it.EntryName != "" {
			name := it.EntryName
			entryName = &name
		}
		_, err := tx.Exec(r.Context(), `
			INSERT INTO meal_template_items (template_id, entry_name, amount, protein_g, carbs_g, fat_g, fiber_g, sugar_g, sort_order)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			templateID,
			entryName,
			it.Amount,
			macroNilInt(it.Macros, "protein"),
			macroNilInt(it.Macros, "carbs"),
			macroNilInt(it.Macros, "fat"),
			macroNilInt(it.Macros, "fiber"),
			macroNilInt(it.Macros, "sugar"),
			idx,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func macroNilInt(m map[string]int, key string) any {
	if v, ok := m[key]; ok {
		return v
	}
	return nil
}
