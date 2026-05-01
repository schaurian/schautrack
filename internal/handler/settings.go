package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"

	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/session"
	"schautrack/internal/sse"
)

type SettingsHandler struct {
	Pool              *pgxpool.Pool
	Broker            *sse.Broker
	AIKeyEncryptSecret string
}

// Preferences handles POST /settings/preferences
func (h *SettingsHandler) Preferences(w http.ResponseWriter, r *http.Request) {
	var body struct {
		WeightUnit string `json:"weight_unit"`
		Timezone   string `json:"timezone"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)
	unit := strings.ToLower(strings.TrimSpace(body.WeightUnit))
	if unit != "kg" && unit != "lb" {
		unit = "kg"
	}

	tz := strings.TrimSpace(body.Timezone)
	if tz != "" {
		if _, err := time.LoadLocation(tz); err != nil {
			tz = ""
		}
	}

	if tz != "" {
		if _, err := h.Pool.Exec(r.Context(), "UPDATE users SET weight_unit = $1, timezone = $2, timezone_manual = TRUE WHERE id = $3", unit, tz, user.ID); err != nil {
			slog.Error("failed to update user preferences", "error", err)
			ErrorJSON(w, http.StatusInternalServerError, "Could not save preferences.")
			return
		}
	} else {
		if _, err := h.Pool.Exec(r.Context(), "UPDATE users SET weight_unit = $1 WHERE id = $2", unit, user.ID); err != nil {
			slog.Error("failed to update user preferences", "error", err)
			ErrorJSON(w, http.StatusInternalServerError, "Could not save preferences.")
			return
		}
	}
	OkJSON(w)
}

// Macros handles POST /settings/macros
func (h *SettingsHandler) Macros(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)

	calorieGoal := parseMacroInputFromBody(body, "calorie_goal")
	enabledMacros := map[string]any{}
	macroGoals := map[string]any{}

	enabledMacros["calories"] = bodyBool(body, "calories_enabled")

	if calorieGoal != nil {
		macroGoals["calories"] = *calorieGoal
	}
	if mode, ok := body["calories_mode"].(string); ok && (mode == "limit" || mode == "target") {
		macroGoals["calories_mode"] = mode
	}

	for _, key := range service.MacroKeys {
		enabledMacros[key] = bodyBool(body, key+"_enabled")
		goal := parseMacroInputFromBody(body, key+"_goal")
		if goal != nil {
			macroGoals[key] = *goal
		}
		if mode, ok := body[key+"_mode"].(string); ok && (mode == "limit" || mode == "target") {
			macroGoals[key+"_mode"] = mode
		}
	}

	wantsAutoCalc := bodyBool(body, "auto_calc_calories")
	canAutoCalc := enabledMacros["calories"] != false &&
		enabledMacros["protein"] == true &&
		enabledMacros["carbs"] == true &&
		enabledMacros["fat"] == true
	enabledMacros["auto_calc_calories"] = wantsAutoCalc && canAutoCalc

	rawThreshold := parseMacroInputFromBody(body, "goal_threshold")
	goalThreshold := 10
	if rawThreshold != nil {
		goalThreshold = max(0, min(*rawThreshold, 99))
	}

	enabledJSON, _ := json.Marshal(enabledMacros)
	goalsJSON, _ := json.Marshal(macroGoals)
	if _, err := h.Pool.Exec(r.Context(),
		"UPDATE users SET macros_enabled = $1, macro_goals = $2, goal_threshold = $3 WHERE id = $4",
		enabledJSON, goalsJSON, goalThreshold, user.ID); err != nil {
		slog.Error("failed to update macro settings", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Could not save macro settings.")
		return
	}

	// Broadcast
	enabledKeys := []string{}
	for _, k := range service.MacroKeys {
		if enabledMacros[k] == true {
			enabledKeys = append(enabledKeys, k)
		}
	}
	macroModes := map[string]any{}
	for _, key := range append([]string{"calories"}, service.MacroKeys...) {
		if v, ok := macroGoals[key+"_mode"]; ok {
			macroModes[key] = v
		}
	}
	h.Broker.BroadcastSettingsChange(user.ID, map[string]any{
		"enabledMacros":    enabledKeys,
		"caloriesEnabled":  enabledMacros["calories"] != false,
		"autoCalcCalories": enabledMacros["auto_calc_calories"],
		"macroGoals":       macroGoals,
		"macroModes":       macroModes,
		"goalThreshold":    goalThreshold,
		"dailyGoal":        macroGoals["calories"],
	})

	OkJSON(w)
}

// AISettings handles POST /settings/ai
func (h *SettingsHandler) AISettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AIKey         string `json:"ai_key"`
		AIProvider    string `json:"ai_provider"`
		AIModel       string `json:"ai_model"`
		AIDailyLimit  string `json:"ai_daily_limit"`
		ClearSettings string `json:"clear_settings"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)

	if body.ClearSettings == "true" {
		if _, err := h.Pool.Exec(r.Context(),
			"UPDATE users SET ai_key = NULL, ai_key_last4 = NULL, ai_endpoint = NULL, ai_model = NULL, ai_daily_limit = NULL, preferred_ai_provider = NULL WHERE id = $1",
			user.ID); err != nil {
			slog.Error("failed to clear AI settings", "error", err)
			ErrorJSON(w, http.StatusInternalServerError, "Could not clear AI settings.")
			return
		}
		JSON(w, http.StatusOK, map[string]any{"ok": true, "message": "AI settings cleared."})
		return
	}

	updates := []string{}
	values := []any{}
	idx := 1

	// Provider
	validProviders := map[string]bool{"openai": true, "claude": true, "ollama": true}
	var newProvider *string
	if validProviders[body.AIProvider] {
		newProvider = &body.AIProvider
	}
	updates = append(updates, fmt.Sprintf("preferred_ai_provider = $%d", idx))
	values = append(values, newProvider)
	idx++

	// API key
	trimmedKey := strings.TrimSpace(body.AIKey)
	if trimmedKey != "" {
		keyToStore := trimmedKey
		if h.AIKeyEncryptSecret != "" {
			if encrypted := service.EncryptApiKey(trimmedKey, h.AIKeyEncryptSecret); encrypted != "" {
				keyToStore = encrypted
			}
		}
		updates = append(updates, fmt.Sprintf("ai_key = $%d", idx))
		values = append(values, keyToStore)
		idx++
		var last4 *string
		if len(trimmedKey) >= 4 {
			s := trimmedKey[len(trimmedKey)-4:]
			last4 = &s
		}
		updates = append(updates, fmt.Sprintf("ai_key_last4 = $%d", idx))
		values = append(values, last4)
		idx++
	} else if newProvider != nil && (user.PreferredAIProvider == nil || *user.PreferredAIProvider != *newProvider) {
		// Clear stored key only when the provider actually changes, since keys are
		// provider-specific. Saves with the same provider and empty key (common with
		// autosave after the input is cleared client-side) must NOT wipe the existing key.
		updates = append(updates, "ai_key = NULL", "ai_key_last4 = NULL")
	}

	// Model
	model := strings.TrimSpace(body.AIModel)
	if len(model) > 100 {
		model = model[:100]
	}
	updates = append(updates, fmt.Sprintf("ai_model = $%d", idx))
	if model == "" {
		values = append(values, nil)
	} else {
		values = append(values, model)
	}
	idx++

	// Daily limit
	limit, err := strconv.Atoi(body.AIDailyLimit)
	updates = append(updates, fmt.Sprintf("ai_daily_limit = $%d", idx))
	if err == nil && limit > 0 {
		values = append(values, limit)
	} else {
		values = append(values, nil)
	}
	idx++

	updates = append(updates, "ai_endpoint = NULL")

	values = append(values, user.ID)
	if _, err := h.Pool.Exec(r.Context(), fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", strings.Join(updates, ", "), idx), values...); err != nil {
		slog.Error("failed to save AI settings", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Could not save AI settings.")
		return
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "message": "AI settings saved."})
}

// Password handles POST /settings/password
func (h *SettingsHandler) Password(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
		TOTPCode        string `json:"totp_code"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)

	if body.CurrentPassword == "" || body.NewPassword == "" {
		ErrorJSON(w, http.StatusBadRequest, "Current and new password are required.")
		return
	}
	if body.NewPassword != body.ConfirmPassword {
		ErrorJSON(w, http.StatusBadRequest, "New passwords do not match.")
		return
	}
	if len(body.NewPassword) < 10 {
		ErrorJSON(w, http.StatusBadRequest, "New password must be at least 10 characters.")
		return
	}

	var passwordHash string
	err := h.Pool.QueryRow(r.Context(), "SELECT password_hash FROM users WHERE id = $1", user.ID).Scan(&passwordHash)
	if err != nil {
		ErrorJSON(w, http.StatusNotFound, "User not found.")
		return
	}

	valid, _ := verifyPassword(passwordHash, body.CurrentPassword)
	if !valid {
		ErrorJSON(w, http.StatusUnauthorized, "Current password is incorrect.")
		return
	}

	if user.TOTPEnabled && user.TOTPSecret != nil {
		if body.TOTPCode == "" {
			ErrorJSON(w, http.StatusBadRequest, "Please enter your 2FA code.")
			return
		}
		if !totp.Validate(body.TOTPCode, *user.TOTPSecret) {
			ErrorJSON(w, http.StatusUnauthorized, "Invalid 2FA code.")
			return
		}
	}

	hash, err := hashPassword(body.NewPassword)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not change password. Please try again.")
		return
	}
	if _, err = h.Pool.Exec(r.Context(), "UPDATE users SET password_hash = $1 WHERE id = $2", hash, user.ID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not change password. Please try again.")
		return
	}
	OkJSON(w)
}

// TwoFactorSetup handles POST /2fa/setup
func (h *SettingsHandler) TwoFactorSetup(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	sess := session.GetSession(r)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Schautrack",
		AccountName: user.Email,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not generate 2FA secret.")
		return
	}

	sess.Set("tempSecret", key.Secret())
	sess.Set("tempUrl", key.URL())
	sess.Set("tempSecretCreatedAt", float64(time.Now().Unix()))

	var qrDataUrl string
	png, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err == nil {
		qrDataUrl = "data:image/png;base64," + encodeBase64(png)
	}

	JSON(w, http.StatusOK, map[string]any{
		"ok": true, "qrDataUrl": qrDataUrl,
		"secret": key.Secret(), "otpauthUrl": key.URL(),
	})
}

// TwoFactorCancel handles POST /2fa/cancel
func (h *SettingsHandler) TwoFactorCancel(w http.ResponseWriter, r *http.Request) {
	sess := session.GetSession(r)
	sess.Delete("tempSecret")
	sess.Delete("tempUrl")
	sess.Delete("tempSecretCreatedAt")
	OkJSON(w)
}

// TwoFactorEnable handles POST /2fa/enable
func (h *SettingsHandler) TwoFactorEnable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	sess := session.GetSession(r)
	secret := sess.GetString("tempSecret")
	if secret == "" {
		ErrorJSON(w, http.StatusBadRequest, "No 2FA setup in progress.")
		return
	}

	if !totp.Validate(body.Token, secret) {
		ErrorJSON(w, http.StatusUnauthorized, "Invalid 2FA code.")
		return
	}

	user := middleware.GetCurrentUser(r)

	// Enable 2FA and generate backup codes in a transaction
	plainCodes := service.GenerateBackupCodes()
	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not enable 2FA.")
		return
	}
	defer tx.Rollback(r.Context())

	if _, err := tx.Exec(r.Context(), "UPDATE users SET totp_secret = $1, totp_enabled = TRUE WHERE id = $2", secret, user.ID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not enable 2FA.")
		return
	}
	// Delete old backup codes
	if _, err := tx.Exec(r.Context(), "DELETE FROM totp_backup_codes WHERE user_id = $1", user.ID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not enable 2FA.")
		return
	}
	for _, code := range plainCodes {
		hash := service.HashBackupCode(code)
		if _, err := tx.Exec(r.Context(), "INSERT INTO totp_backup_codes (user_id, code_hash) VALUES ($1, $2)", user.ID, hash); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not enable 2FA.")
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not enable 2FA.")
		return
	}

	sess.Delete("tempSecret")
	sess.Delete("tempUrl")
	sess.Delete("tempSecretCreatedAt")
	JSON(w, http.StatusOK, map[string]any{"ok": true, "backupCodes": plainCodes})
}

// TwoFactorDisable handles POST /2fa/disable
func (h *SettingsHandler) TwoFactorDisable(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token      string `json:"token"`
		BackupCode string `json:"backup_code"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)
	if !user.TOTPEnabled || user.TOTPSecret == nil {
		ErrorJSON(w, http.StatusBadRequest, "2FA is not enabled.")
		return
	}

	verified := false
	if body.Token != "" {
		verified = totp.Validate(body.Token, *user.TOTPSecret)
	}
	if !verified && body.BackupCode != "" {
		verified = h.verifyAndUseBackupCode(r, user.ID, body.BackupCode)
	}
	if !verified {
		ErrorJSON(w, http.StatusUnauthorized, "Invalid 2FA code or backup code.")
		return
	}

	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not disable 2FA.")
		return
	}
	defer tx.Rollback(r.Context())

	if _, err := tx.Exec(r.Context(), "UPDATE users SET totp_secret = NULL, totp_enabled = FALSE WHERE id = $1", user.ID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not disable 2FA.")
		return
	}
	if _, err := tx.Exec(r.Context(), "DELETE FROM totp_backup_codes WHERE user_id = $1", user.ID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not disable 2FA.")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not disable 2FA.")
		return
	}
	OkJSON(w)
}

// RegenerateBackupCodes handles POST /2fa/backup-codes
func (h *SettingsHandler) RegenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)
	if !user.TOTPEnabled || user.TOTPSecret == nil {
		ErrorJSON(w, http.StatusBadRequest, "2FA is not enabled.")
		return
	}

	if !totp.Validate(body.Token, *user.TOTPSecret) {
		ErrorJSON(w, http.StatusUnauthorized, "Invalid 2FA code.")
		return
	}

	plainCodes := service.GenerateBackupCodes()
	tx, err := h.Pool.Begin(r.Context())
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not regenerate codes.")
		return
	}
	defer tx.Rollback(r.Context())

	if _, err := tx.Exec(r.Context(), "DELETE FROM totp_backup_codes WHERE user_id = $1", user.ID); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not regenerate codes.")
		return
	}
	for _, code := range plainCodes {
		hash := service.HashBackupCode(code)
		if _, err := tx.Exec(r.Context(), "INSERT INTO totp_backup_codes (user_id, code_hash) VALUES ($1, $2)", user.ID, hash); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not regenerate codes.")
			return
		}
	}
	if err := tx.Commit(r.Context()); err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not regenerate codes.")
		return
	}

	JSON(w, http.StatusOK, map[string]any{"ok": true, "backupCodes": plainCodes})
}

// verifyAndUseBackupCode checks a backup code against stored hashes and marks it used atomically.
func (h *SettingsHandler) verifyAndUseBackupCode(r *http.Request, userID int, code string) bool {
	return verifyAndMarkBackupCode(r, h.Pool, userID, code)
}

// --- Links handler ---

type LinksHandler struct {
	Pool   *pgxpool.Pool
	Broker *sse.Broker
}

const MaxLinks = 10

// LinkRequest handles POST /settings/link/request
func (h *LinksHandler) LinkRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	email := strings.TrimSpace(body.Email)
	if email == "" {
		ErrorJSON(w, http.StatusBadRequest, "Email is required.")
		return
	}

	user := middleware.GetCurrentUser(r)

	var targetID int
	var targetEmail string
	err := h.Pool.QueryRow(r.Context(), "SELECT id, email FROM users WHERE LOWER(email) = LOWER($1)", email).Scan(&targetID, &targetEmail)
	if err != nil {
		JSON(w, http.StatusNotFound, map[string]any{"ok": false, "message": "No account found for that email."})
		return
	}
	if targetID == user.ID {
		JSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "You cannot link to your own account."})
		return
	}

	// Check existing link
	var existingStatus *string
	var existingRequesterID *int
	if err := h.Pool.QueryRow(r.Context(), `
		SELECT status, requester_id FROM account_links
		WHERE LEAST(requester_id, target_id) = LEAST($1, $2)
			AND GREATEST(requester_id, target_id) = GREATEST($1, $2) LIMIT 1`,
		user.ID, targetID).Scan(&existingStatus, &existingRequesterID); err != nil {
		// pgx.ErrNoRows is expected when no link exists — only log unexpected errors
		existingStatus = nil
	}

	if existingStatus != nil {
		if *existingStatus == "accepted" {
			JSON(w, http.StatusConflict, map[string]any{"ok": false, "message": "You are already linked with this account."})
		} else if existingRequesterID != nil && *existingRequesterID == user.ID {
			JSON(w, http.StatusConflict, map[string]any{"ok": false, "message": "Request already sent and pending approval."})
		} else {
			JSON(w, http.StatusConflict, map[string]any{"ok": false, "message": "They already sent you a request. Check incoming requests below."})
		}
		return
	}

	myCount, _ := service.CountAcceptedLinks(r.Context(), h.Pool, user.ID)
	if myCount >= MaxLinks {
		JSON(w, http.StatusConflict, map[string]any{"ok": false, "message": fmt.Sprintf("You already have %d linked accounts.", MaxLinks)})
		return
	}
	targetCount, _ := service.CountAcceptedLinks(r.Context(), h.Pool, targetID)
	if targetCount >= MaxLinks {
		JSON(w, http.StatusConflict, map[string]any{"ok": false, "message": "The other account already reached the linking limit."})
		return
	}

	var insertedID int
	var createdAt time.Time
	err = h.Pool.QueryRow(r.Context(),
		"INSERT INTO account_links (requester_id, target_id, status) VALUES ($1, $2, 'pending') RETURNING id, created_at",
		user.ID, targetID).Scan(&insertedID, &createdAt)
	if err != nil {
		ErrorJSON(w, http.StatusInternalServerError, "Could not send link request.")
		return
	}

	h.Broker.BroadcastLinkChange(targetID, "request", map[string]any{
		"requestId": insertedID, "email": user.Email, "created_at": createdAt,
	})

	JSON(w, http.StatusOK, map[string]any{
		"ok": true, "message": fmt.Sprintf("Request sent to %s.", targetEmail),
		"request": map[string]any{"id": insertedID, "email": targetEmail, "created_at": createdAt},
	})
}

// LinkRespond handles POST /settings/link/respond
func (h *LinksHandler) LinkRespond(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RequestID int    `json:"request_id"`
		Action    string `json:"action"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	if body.RequestID == 0 || (body.Action != "accept" && body.Action != "decline") {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	user := middleware.GetCurrentUser(r)

	var requesterID, targetID int
	var status string
	err := h.Pool.QueryRow(r.Context(),
		"SELECT requester_id, target_id, status FROM account_links WHERE id = $1 AND status = 'pending' LIMIT 1",
		body.RequestID).Scan(&requesterID, &targetID, &status)
	if err != nil || targetID != user.ID {
		JSON(w, http.StatusNotFound, map[string]any{"ok": false, "message": "Request not found."})
		return
	}

	if body.Action == "accept" {
		tx, err := h.Pool.Begin(r.Context())
		if err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not update request.")
			return
		}
		defer tx.Rollback(r.Context())

		// Check link limits within transaction
		var myCount, reqCount int
		if err := tx.QueryRow(r.Context(),
			"SELECT COUNT(*) FROM account_links WHERE status = 'accepted' AND (requester_id = $1 OR target_id = $1)", user.ID).Scan(&myCount); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not check link limits.")
			return
		}
		if myCount >= MaxLinks {
			JSON(w, http.StatusConflict, map[string]any{"ok": false, "message": fmt.Sprintf("You already have %d linked accounts.", MaxLinks)})
			return
		}
		if err := tx.QueryRow(r.Context(),
			"SELECT COUNT(*) FROM account_links WHERE status = 'accepted' AND (requester_id = $1 OR target_id = $1)", requesterID).Scan(&reqCount); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not check link limits.")
			return
		}
		if reqCount >= MaxLinks {
			JSON(w, http.StatusConflict, map[string]any{"ok": false, "message": "The requester is already at the link limit."})
			return
		}

		if _, err := tx.Exec(r.Context(), "UPDATE account_links SET status = 'accepted', updated_at = NOW() WHERE id = $1", body.RequestID); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not accept link request.")
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not accept link request.")
			return
		}

		h.Broker.BroadcastLinkChange(requesterID, "accepted", map[string]any{
			"linkId": body.RequestID, "userId": user.ID, "email": user.Email,
		})
		JSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Link request accepted."})
	} else {
		if _, err := h.Pool.Exec(r.Context(), "DELETE FROM account_links WHERE id = $1 AND target_id = $2", body.RequestID, user.ID); err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not decline request.")
			return
		}
		h.Broker.BroadcastLinkChange(requesterID, "declined", map[string]any{
			"requestId": body.RequestID, "email": user.Email,
		})
		JSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Request declined."})
	}
}

// LinkRemove handles POST /settings/link/remove
func (h *LinksHandler) LinkRemove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		LinkID int `json:"link_id"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	if body.LinkID == 0 {
		ErrorJSON(w, http.StatusBadRequest, "Invalid link.")
		return
	}

	user := middleware.GetCurrentUser(r)

	var delStatus string
	var delRequesterID, delTargetID int
	err := h.Pool.QueryRow(r.Context(),
		"DELETE FROM account_links WHERE id = $1 AND (requester_id = $2 OR target_id = $2) RETURNING status, requester_id, target_id",
		body.LinkID, user.ID).Scan(&delStatus, &delRequesterID, &delTargetID)
	if err != nil {
		JSON(w, http.StatusNotFound, map[string]any{"ok": false, "message": "Link not found."})
		return
	}

	otherID := delTargetID
	if delRequesterID != user.ID {
		otherID = delRequesterID
	}

	if delStatus == "accepted" {
		h.Broker.BroadcastLinkChange(otherID, "removed", map[string]any{"linkId": body.LinkID})
		JSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Link removed."})
	} else {
		h.Broker.BroadcastLinkChange(otherID, "cancelled", map[string]any{"requestId": body.LinkID})
		JSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Request cancelled."})
	}
}

// LinkLabel handles POST /links/:id/label
func (h *LinksHandler) LinkLabel(w http.ResponseWriter, r *http.Request) {
	linkID, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid link")
		return
	}

	var body struct {
		Label string `json:"label"`
	}
	if err := ReadJSON(r, &body); err != nil {
		ErrorJSON(w, http.StatusBadRequest, "Invalid request.")
		return
	}

	label := strings.TrimSpace(body.Label)
	if len(label) > 120 {
		label = label[:120]
	}
	var labelPtr *string
	if label != "" {
		labelPtr = &label
	}

	user := middleware.GetCurrentUser(r)

	var updatedID int
	var updatedLabel *string
	err = h.Pool.QueryRow(r.Context(), `
		UPDATE account_links
		SET requester_label = CASE WHEN requester_id = $3 THEN $1 ELSE requester_label END,
			target_label = CASE WHEN target_id = $3 THEN $1 ELSE target_label END,
			updated_at = NOW()
		WHERE id = $2 AND status = 'accepted' AND ($3 = requester_id OR $3 = target_id)
		RETURNING id, CASE WHEN requester_id = $3 THEN requester_label ELSE target_label END AS label`,
		labelPtr, linkID, user.ID).Scan(&updatedID, &updatedLabel)

	if err != nil {
		ErrorJSON(w, http.StatusNotFound, "Link not found")
		return
	}

	h.Broker.BroadcastLinkLabelChange(updatedID, user.ID, label)
	var respLabel any
	if updatedLabel != nil {
		respLabel = *updatedLabel
	}
	JSON(w, http.StatusOK, map[string]any{"ok": true, "label": respLabel})
}

// --- helpers ---

func bodyBool(body map[string]any, key string) bool {
	v := body[key]
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val == "on" || val == "true"
	}
	return false
}

func parseMacroInputFromBody(body map[string]any, key string) *int {
	v, ok := body[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case float64:
		n := int(val)
		if n < 0 {
			return nil
		}
		return &n
	case string:
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 {
			return nil
		}
		return &n
	}
	return nil
}

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
