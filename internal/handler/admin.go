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

// UpdateSettings handles POST /admin/settings.
//
// Both single ({key, value}) and batch ({settings: {...}}) bodies are
// accepted. Validates against the canonical adminSettings list:
//   - the key must be in the allowlist
//   - the env var must not override the setting
//   - the value must pass the per-key validator (if any)
// All checks run before any write, so a batch save is all-or-nothing.
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

	// Normalise single → batch so we have one validation+write path.
	pending := body.Settings
	if pending == nil {
		if body.Key == "" {
			ErrorJSON(w, http.StatusBadRequest, "Missing setting key.")
			return
		}
		pending = map[string]string{body.Key: body.Value}
	}

	// Validate everything first.
	for k, v := range pending {
		spec, ok := adminSettingByKey[k]
		if !ok {
			ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Invalid setting key: %s", k))
			return
		}
		if os.Getenv(spec.Env) != "" {
			ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("Setting '%s' is controlled by environment variable.", k))
			return
		}
		if spec.Validate != nil {
			if err := spec.Validate(v); err != nil {
				ErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("%s: %s", k, err.Error()))
				return
			}
		}
	}

	// Write + audit.
	user := middleware.GetCurrentUser(r)
	var actorID *int
	if user != nil {
		actorID = &user.ID
	}
	for k, v := range pending {
		if err := h.Settings.SetAdminSetting(r.Context(), k, v); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Failed to update settings.")
			return
		}
		// Capture *what* changed; for secret keys we only log the key name
		// and whether a value was set, never the value itself.
		spec := adminSettingByKey[k]
		meta := map[string]any{"key": k}
		if spec != nil && spec.Secret {
			meta["value_set"] = v != ""
		} else {
			meta["value"] = v
		}
		service.WriteAudit(r.Context(), h.Pool, h.Cfg.TrustProxy, actorID, service.AuditAdminSettingChanged, r, meta)
	}
	if body.Settings != nil {
		JSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Settings updated."})
	} else {
		JSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Setting updated."})
	}
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

	// Clean up sessions (not FK-linked to users)
	if _, err := tx.Exec(r.Context(), `DELETE FROM "session" WHERE (sess::jsonb->>'userId')::int = $1`, userID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Failed to delete user.")
		return
	}
	// Delete user — all child tables use ON DELETE CASCADE
	if _, err := tx.Exec(r.Context(), "DELETE FROM users WHERE id = $1", userID); err != nil {
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
		"INSERT INTO invite_codes (code, email, created_by, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '14 days') RETURNING id",
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
