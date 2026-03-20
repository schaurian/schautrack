package handler

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/service"
)

type AdminHandler struct {
	Pool     *pgxpool.Pool
	Settings *database.SettingsCache
	Cfg      *config.Config
	Email    *service.EmailService
}

var allowedAdminKeys = map[string]string{
	"support_email":     "SUPPORT_EMAIL",
	"imprint_address":   "IMPRINT_ADDRESS",
	"imprint_email":     "IMPRINT_EMAIL",
	"enable_legal":      "ENABLE_LEGAL",
	"ai_provider":       "AI_PROVIDER",
	"ai_key":            "AI_KEY",
	"ai_endpoint":       "AI_ENDPOINT",
	"ai_model":          "AI_MODEL",
	"ai_daily_limit":    "AI_DAILY_LIMIT",
	"enable_registration": "ENABLE_REGISTRATION",
	"enable_barcode":    "ENABLE_BARCODE",
}

// UpdateSettings handles POST /admin/settings
func (h *AdminHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key      string            `json:"key"`
		Value    string            `json:"value"`
		Settings map[string]string `json:"settings"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	// Batch mode
	if body.Settings != nil {
		for k := range body.Settings {
			envVar, ok := allowedAdminKeys[k]
			if !ok {
				ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Invalid setting key: %s", k))
				return
			}
			if os.Getenv(envVar) != "" {
				ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Setting '%s' is controlled by environment variable.", k))
				return
			}
		}
		for k, v := range body.Settings {
			if err := h.Settings.SetAdminSetting(r.Context(), k, v); err != nil {
				ErrorJSON(w, http.StatusInternalServerError, "Failed to update settings.")
				return
			}
		}
		JSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Settings updated."})
		return
	}

	// Single mode
	envVar, ok := allowedAdminKeys[body.Key]
	if !ok {
		ErrorJSON(w, http.StatusBadRequest, "Invalid setting key.")
		return
	}
	if os.Getenv(envVar) != "" {
		ErrorJSON(w, http.StatusBadRequest, "This setting is controlled by environment variable.")
		return
	}
	if err := h.Settings.SetAdminSetting(r.Context(), body.Key, body.Value); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to update setting.")
		return
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Setting updated."})
}

// DeleteUser handles POST /admin/users/:id/delete
func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid user ID.")
		return
	}

	currentUser := middleware.GetCurrentUser(r)
	if userID == currentUser.ID {
		ErrorJSON(w, http.StatusBadRequest, "Cannot delete yourself.")
		return
	}

	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to delete user.")
		return
	}
	defer tx.Rollback(r.Context())

	tables := []string{
		"DELETE FROM totp_backup_codes WHERE user_id = $1",
		"DELETE FROM daily_notes WHERE user_id = $1",
		"DELETE FROM calorie_entries WHERE user_id = $1",
		"DELETE FROM weight_entries WHERE user_id = $1",
		"DELETE FROM ai_usage WHERE user_id = $1",
		"DELETE FROM account_links WHERE requester_id = $1 OR target_id = $1",
		"DELETE FROM password_reset_tokens WHERE user_id = $1",
		"DELETE FROM email_verification_tokens WHERE user_id = $1",
		"DELETE FROM users WHERE id = $1",
	}
	for _, q := range tables {
		if _, err := tx.Exec(r.Context(), q, userID); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Failed to delete user.")
			return
		}
	}
	// Clean up sessions
	if _, err := tx.Exec(r.Context(), `DELETE FROM "session" WHERE (sess::jsonb->>'userId')::int = $1`, userID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to delete user.")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to delete user.")
		return
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "message": "User deleted completely."})
}

// CreateInvite handles POST /admin/invites
func (h *AdminHandler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	ReadJSON(r, &body)

	user := middleware.GetCurrentUser(r)
	code := service.GenerateInviteCode()
	email := strings.TrimSpace(body.Email)

	var emailPtr *string
	if email != "" {
		emailPtr = &email
	}

	var id int
	err := h.Pool.QueryRow(r.Context(),
		"INSERT INTO invite_codes (code, email, created_by) VALUES ($1, $2, $3) RETURNING id",
		code, emailPtr, user.ID).Scan(&id)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to create invite.")
		return
	}

	// Send email if address provided and SMTP is configured
	if email != "" && h.Email.IsConfigured() {
		baseURL := h.Cfg.BaseURL
		if baseURL == "" {
			baseURL = "https://" + r.Host
		}
		h.Email.SendInviteEmail(email, code, baseURL)
	}

	JSON(w, http.StatusOK, map[string]any{
		"ok": true, "invite": map[string]any{
			"id": id, "code": code, "email": emailPtr,
		},
	})
}

// ListInvites handles GET /admin/invites
func (h *AdminHandler) ListInvites(w http.ResponseWriter, r *http.Request) {
	rows, err := h.Pool.Query(r.Context(), `
		SELECT ic.id, ic.code, ic.email, ic.used_by, u.email AS used_by_email, ic.expires_at, ic.created_at
		FROM invite_codes ic
		LEFT JOIN users u ON u.id = ic.used_by
		ORDER BY ic.created_at DESC
		LIMIT 100`)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to load invites.")
		return
	}
	defer rows.Close()

	var invites []map[string]any
	for rows.Next() {
		var id int
		var code string
		var email, usedByEmail *string
		var usedBy *int
		var expiresAt, createdAt interface{}
		if err := rows.Scan(&id, &code, &email, &usedBy, &usedByEmail, &expiresAt, &createdAt); err != nil {
			continue
		}
		invites = append(invites, map[string]any{
			"id": id, "code": code, "email": email,
			"used_by": usedBy, "used_by_email": usedByEmail,
			"expires_at": expiresAt, "created_at": createdAt,
		})
	}
	if invites == nil {
		invites = []map[string]any{}
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "invites": invites})
}

// DeleteInvite handles POST /admin/invites/:id/delete
func (h *AdminHandler) DeleteInvite(w http.ResponseWriter, r *http.Request) {
	inviteID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid invite ID.")
		return
	}
	tag, err := h.Pool.Exec(r.Context(), "DELETE FROM invite_codes WHERE id = $1 AND used_by IS NULL", inviteID)
	if err != nil || tag.RowsAffected() == 0 {
		ErrorJSON(w, http.StatusNotFound, "Invite not found or already used.")
		return
	}
	OkJSON(w)
}

// Suppress unused
var _ = strings.TrimSpace
