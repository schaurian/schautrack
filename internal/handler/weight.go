package handler

import (
	"fmt"
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

// WeightDay handles GET /weight/day
func (h *WeightHandler) WeightDay(w http.ResponseWriter, r *http.Request) {
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
	if !dateRe.MatchString(dateStr) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid date")
		return
	}

	weightStr := fmt.Sprintf("%v", body["weight"])
	wr := service.ParseWeight(weightStr)
	if !wr.Ok {
		ErrorJSON(w, http.StatusBadRequest, "Invalid weight")
		return
	}

	entry, err := service.UpsertWeightEntry(r.Context(), h.Pool, user.ID, dateStr, wr.Value)
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
	if _, err := h.Pool.Exec(r.Context(), "DELETE FROM weight_entries WHERE id = $1 AND user_id = $2", weightID, user.ID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to delete weight entry")
		return
	}
	if h.Broker != nil {
		h.Broker.BroadcastEntryChange(user.ID)
	}
	OkJSON(w)
}

