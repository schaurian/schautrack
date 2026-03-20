package handler

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/middleware"
	"schautrack/internal/sse"
)

type NotesHandler struct {
	Pool   *pgxpool.Pool
	Broker *sse.Broker
}

// ToggleEnabled handles POST /api/notes/toggle-enabled
func (h *NotesHandler) ToggleEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled any `json:"enabled"`
	}
	ReadJSON(r, &body)
	enabled := body.Enabled == true || body.Enabled == "true"
	user := middleware.GetCurrentUser(r)
	if _, err := h.Pool.Exec(r.Context(), "UPDATE users SET notes_enabled = $1 WHERE id = $2", enabled, user.ID); err != nil {
		slog.Error("failed to toggle notes enabled", "error", err)
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "enabled": enabled})
}

// Get handles GET /api/notes/day?date=...&user=...
func (h *NotesHandler) Get(w http.ResponseWriter, r *http.Request) {
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

	var notesEnabled bool
	if err := h.Pool.QueryRow(r.Context(), "SELECT notes_enabled FROM users WHERE id = $1", targetUserID).Scan(&notesEnabled); err != nil {
		slog.Error("failed to check notes_enabled", "error", err)
	}
	if !notesEnabled {
		JSON(w, http.StatusOK, map[string]any{"ok": true, "content": "", "enabled": false})
		return
	}

	var content string
	err := h.Pool.QueryRow(r.Context(),
		"SELECT content FROM daily_notes WHERE user_id = $1 AND note_date = $2",
		targetUserID, dateStr).Scan(&content)
	if err != nil {
		content = ""
	}

	JSON(w, http.StatusOK, map[string]any{"ok": true, "content": content, "enabled": true})
}

// Save handles POST /api/notes
func (h *NotesHandler) Save(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Date    string `json:"date"`
		Content string `json:"content"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	if !dateRe.MatchString(body.Date) {
		ErrorJSON(w, http.StatusBadRequest, "Invalid date")
		return
	}

	user := middleware.GetCurrentUser(r)
	content := strings.TrimSpace(body.Content)

	if len(content) > 10000 {
		content = content[:10000]
	}

	if content == "" {
		// Delete the note
		if _, err := h.Pool.Exec(r.Context(),
			"DELETE FROM daily_notes WHERE user_id = $1 AND note_date = $2",
			user.ID, body.Date); err != nil {
			slog.Error("failed to delete note", "error", err)
			ErrorJSON(w, http.StatusInternalServerError, "Failed to save note.")
			return
		}
	} else {
		// Upsert
		if _, err := h.Pool.Exec(r.Context(), `
			INSERT INTO daily_notes (user_id, note_date, content, updated_at)
			VALUES ($1, $2, $3, NOW())
			ON CONFLICT (user_id, note_date) DO UPDATE SET content = $3, updated_at = NOW()`,
			user.ID, body.Date, content); err != nil {
			slog.Error("failed to save note", "error", err)
			ErrorJSON(w, http.StatusInternalServerError, "Failed to save note.")
			return
		}
	}

	h.Broker.BroadcastNoteChange(user.ID)
	OkJSON(w)
}
