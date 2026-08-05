package handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/sse"
)

type WeightHandler struct {
	Pool   *pgxpool.Pool
	Broker *sse.Broker
}

// ToggleBodyFatEnabled handles POST /weight/toggle-body-fat. The flag only
// governs whether the UI offers the field — the upsert endpoints accept a
// body_fat regardless, so an import or an API client is never blocked by a
// preference the user has not visited.
func (h *WeightHandler) ToggleBodyFatEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled any `json:"enabled"`
	}
	ReadJSON(r, &body)
	enabled := body.Enabled == true || body.Enabled == "true"
	user := middleware.GetCurrentUser(r)
	if _, err := h.Pool.Exec(r.Context(), "UPDATE users SET body_fat_enabled = $1 WHERE id = $2", enabled, user.ID); err != nil {
		slog.Error("failed to toggle body fat enabled", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Could not save setting.")
		return
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": enabled})
}

// parseBodyFatUpdate maps the optional body_fat field of a decoded JSON body
// onto the three states of a service.BodyFatUpdate: an absent key leaves any
// stored reading alone, an explicit null or empty string clears it, and a
// number sets it. The bool is false only when a value was supplied but is
// unusable, so the caller can answer 400 instead of silently dropping it.
func parseBodyFatUpdate(body map[string]any) (service.BodyFatUpdate, bool) {
	raw, exists := body["body_fat"]
	if !exists {
		return service.KeepBodyFat, true
	}
	if raw == nil {
		return service.BodyFatUpdate{Set: true}, true
	}
	s := strings.TrimSpace(fmt.Sprintf("%v", raw))
	if s == "" || s == "<nil>" {
		return service.BodyFatUpdate{Set: true}, true
	}
	pct, ok := service.ParseBodyFat(s)
	if !ok {
		return service.BodyFatUpdate{}, false
	}
	return service.BodyFatUpdate{Set: true, Value: &pct}, true
}

// WeightDay handles GET /weight/day
func (h *WeightHandler) WeightDay(w http.ResponseWriter, r *http.Request) {
	dateStr := strings.TrimSpace(r.URL.Query().Get("date"))
	if !isValidDate(dateStr) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid date")
		return
	}

	user := middleware.GetCurrentUser(r)
	targetUser := middleware.GetTargetUser(r)
	if targetUser == nil {
		targetUser = user
	}
	targetUserID := targetUser.ID
	tz := getUserTimezone(r, user)
	if targetUserID != user.ID {
		tz = targetUser.GetTimezone()
		if tz == "" {
			tz = "UTC"
		}
	}

	entry, err := service.GetWeightEntry(r.Context(), h.Pool, targetUserID, dateStr)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not load weight")
		return
	}
	lastWeight, _ := service.GetLastWeightEntry(r.Context(), h.Pool, targetUserID, dateStr)

	var entryResp any = entry
	var lastResp any = lastWeight
	if entry != nil {
		entryResp = map[string]any{
			"id": entry.ID, "entry_date": entry.Date, "weight": entry.Weight,
			"body_fat":   entry.BodyFat,
			"created_at": entry.CreatedAt, "updated_at": entry.UpdatedAt,
			"timeFormatted": service.FormatTimeInTz(entry.UpdatedAt, tz),
		}
	}

	JSON(w, http.StatusOK, map[string]any{"ok": true, "entry": entryResp, "lastWeight": lastResp})
}

// WeightUpsert handles POST /weight/upsert
func (h *WeightHandler) WeightUpsert(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)
	userTz := getUserTimezone(r, user)

	dateStr := strings.TrimSpace(fmt.Sprintf("%v", body["entry_date"]))
	if dateStr == "" || dateStr == "<nil>" {
		dateStr = strings.TrimSpace(fmt.Sprintf("%v", body["date"]))
	}
	if dateStr == "" || dateStr == "<nil>" {
		dateStr = service.FormatDateInTz(time.Now(), userTz)
	}
	if !isValidDate(dateStr) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid date")
		return
	}

	weightStr := fmt.Sprintf("%v", body["weight"])
	wr := service.ParseWeight(weightStr)
	if !wr.Ok {
		ErrorJSON(w, http.StatusBadRequest, "Invalid weight")
		return
	}

	bodyFat, ok := parseBodyFatUpdate(body)
	if !ok {
		ErrorJSON(w, http.StatusBadRequest, "Invalid body fat")
		return
	}

	entry, err := service.UpsertWeightEntry(r.Context(), h.Pool, user.ID, dateStr, wr.Value, bodyFat)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not save weight")
		return
	}
	if h.Broker != nil {
		h.Broker.BroadcastEntryChange(user.ID)
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "entry": entry})
}

// WeightDelete handles POST /weight/:id/delete
func (h *WeightHandler) WeightDelete(w http.ResponseWriter, r *http.Request) {
	weightID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid id")
		return
	}
	user := middleware.GetCurrentUser(r)
	tag, err := h.Pool.Exec(r.Context(), "DELETE FROM weight_entries WHERE id = $1 AND user_id = $2", weightID, user.ID)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to delete weight entry")
		return
	}
	if tag.RowsAffected() == 0 {
		ErrorJSON(w, http.StatusNotFound, "Weight entry not found")
		return
	}
	if h.Broker != nil {
		h.Broker.BroadcastEntryChange(user.ID)
	}
	OkJSON(w)
}
