package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/config"
	"schautrack/internal/database"
	"schautrack/internal/middleware"
	"schautrack/internal/service"
	"schautrack/internal/session"
)

// CsrfToken handles GET /api/csrf
func CsrfToken(w http.ResponseWriter, r *http.Request) {
	sess := session.GetSession(r)
	token := session.GenerateCsrfToken(sess)
	JSON(w, http.StatusOK, map[string]any{"token": token})
}

// Me handles GET /api/me
func Me(adminEmail string, settingsCache *database.SettingsCache, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.GetCurrentUser(r)
		if user == nil {
			ErrorJSON(w, http.StatusUnauthorized, "Not authenticated")
			return
		}

		var macrosEnabled, macroGoals any
		json.Unmarshal(user.MacrosEnabled, &macrosEnabled)
		json.Unmarshal(user.MacroGoals, &macroGoals)

		if macrosEnabled == nil {
			macrosEnabled = map[string]any{}
		}
		if macroGoals == nil {
			macroGoals = map[string]any{}
		}

		tz := "UTC"
		if user.Timezone != nil {
			tz = *user.Timezone
		}

		globalKey := settingsCache.GetEffectiveSetting(r.Context(), "ai_key", cfg.AIKey)
		hasGlobalAiKey := globalKey.Value != nil && *globalKey.Value != ""
		globalProviderResult := settingsCache.GetEffectiveSetting(r.Context(), "ai_provider", cfg.AIProvider)
		hasGlobalAiConfig := hasGlobalAiKey || (globalProviderResult.Value != nil && *globalProviderResult.Value != "")

		JSON(w, http.StatusOK, map[string]any{
			"user": map[string]any{
				"id":                  user.ID,
				"email":              user.Email,
				"timezone":           tz,
				"weightUnit":         user.WeightUnit,
				"dailyGoal":          user.DailyGoal,
				"totpEnabled":        user.TOTPEnabled,
				"macrosEnabled":      macrosEnabled,
				"macroGoals":         macroGoals,
				"goalThreshold":      user.GoalThreshold,
				"preferredAiProvider": nilStr(user.PreferredAIProvider),
				"hasAiKey":           user.AIKey != nil && *user.AIKey != "",
				"hasGlobalAiKey":     hasGlobalAiKey,
				"hasGlobalAiConfig":  hasGlobalAiConfig,
				"aiModel":            user.AIModel,
				"aiDailyLimit":       user.AIDailyLimit,
				"todosEnabled":       user.TodosEnabled,
				"notesEnabled":       user.NotesEnabled,
			},
			"isAdmin": middleware.IsAdmin(user, adminEmail),
		})
	}
}

// Settings handles GET /api/settings
func Settings(pool *pgxpool.Pool, adminEmail string, settingsCache *database.SettingsCache, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := middleware.GetCurrentUser(r)
		sess := session.GetSession(r)

		var macrosEnabled, macroGoals any
		json.Unmarshal(user.MacrosEnabled, &macrosEnabled)
		json.Unmarshal(user.MacroGoals, &macroGoals)
		if macrosEnabled == nil {
			macrosEnabled = map[string]any{}
		}
		if macroGoals == nil {
			macroGoals = map[string]any{}
		}

		tz := "UTC"
		if user.Timezone != nil {
			tz = *user.Timezone
		}

		hasAiKey := user.AIKey != nil && *user.AIKey != ""
		aiKeyLast4 := ""
		if user.AIKeyLast4 != nil {
			aiKeyLast4 = *user.AIKeyLast4
		}

		globalKey := settingsCache.GetEffectiveSetting(r.Context(), "ai_key", cfg.AIKey)
		hasGlobalAiKey := globalKey.Value != nil && *globalKey.Value != ""

		hasTempSecret := sess.GetString("tempSecret") != ""

		const maxLinks = MaxLinks

		// Build user response
		userResp := map[string]any{
			"id":                 user.ID,
			"email":              user.Email,
			"timezone":           tz,
			"weightUnit":         user.WeightUnit,
			"totpEnabled":        user.TOTPEnabled,
			"macrosEnabled":      macrosEnabled,
			"macroGoals":         macroGoals,
			"goalThreshold":      user.GoalThreshold,
			"preferredAiProvider": nilStr(user.PreferredAIProvider),
			"hasAiKey":           hasAiKey,
			"aiKeyLast4":         aiKeyLast4,
			"aiModel":            user.AIModel,
			"aiDailyLimit":       user.AIDailyLimit,
			"todosEnabled":       user.TodosEnabled,
			"notesEnabled":       user.NotesEnabled,
			"hasGlobalAiKey":     hasGlobalAiKey,
		}

		// Load link state
		linkState, _ := service.GetLinkRequests(r.Context(), pool, user.ID)
		acceptedLinks, _ := service.GetAcceptedLinkUsers(r.Context(), pool, user.ID)
		availableSlots := maxLinks - len(acceptedLinks)
		if availableSlots < 0 {
			availableSlots = 0
		}

		resp := map[string]any{
			"user":             userResp,
			"hasTempSecret":    hasTempSecret,
			"incomingRequests": linkState.Incoming,
			"outgoingRequests": linkState.Outgoing,
			"acceptedLinks":    acceptedLinks,
			"maxLinks":         maxLinks,
			"availableSlots":   availableSlots,
			"timezones":        getTimezones(),
			"linkFeedback":     sess.Get("linkFeedback"),
			"passwordFeedback": sess.Get("passwordFeedback"),
			"aiFeedback":       sess.Get("aiFeedback"),
			"emailFeedback":    sess.Get("emailFeedback"),
			"importFeedback":   sess.Get("importFeedback"),
		}

		// Clear feedback after sending
		sess.Delete("linkFeedback")
		sess.Delete("passwordFeedback")
		sess.Delete("aiFeedback")
		sess.Delete("emailFeedback")
		sess.Delete("importFeedback")

		JSON(w, http.StatusOK, resp)
	}
}

func nilStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func getTimezones() []string {
	// Common IANA timezone list
	zones := []string{
		"Africa/Abidjan", "Africa/Cairo", "Africa/Johannesburg", "Africa/Lagos", "Africa/Nairobi",
		"America/Anchorage", "America/Argentina/Buenos_Aires", "America/Bogota", "America/Chicago",
		"America/Denver", "America/Los_Angeles", "America/Mexico_City", "America/New_York",
		"America/Phoenix", "America/Sao_Paulo", "America/Toronto", "America/Vancouver",
		"Asia/Bangkok", "Asia/Calcutta", "Asia/Dubai", "Asia/Hong_Kong", "Asia/Jakarta",
		"Asia/Kolkata", "Asia/Seoul", "Asia/Shanghai", "Asia/Singapore", "Asia/Tokyo",
		"Atlantic/Reykjavik", "Australia/Melbourne", "Australia/Perth", "Australia/Sydney",
		"Europe/Amsterdam", "Europe/Athens", "Europe/Berlin", "Europe/Brussels", "Europe/Budapest",
		"Europe/Dublin", "Europe/Helsinki", "Europe/Istanbul", "Europe/Kiev", "Europe/Lisbon",
		"Europe/London", "Europe/Madrid", "Europe/Moscow", "Europe/Oslo", "Europe/Paris",
		"Europe/Prague", "Europe/Rome", "Europe/Stockholm", "Europe/Vienna", "Europe/Warsaw",
		"Europe/Zurich", "Pacific/Auckland", "Pacific/Fiji", "Pacific/Honolulu", "UTC",
	}
	// Try to get full list from system
	if full := getSystemTimezones(); len(full) > 0 {
		return full
	}
	return zones
}

func getSystemTimezones() []string {
	// Go doesn't have an equivalent of Intl.supportedValuesOf('timeZone'),
	// but we can try reading the zoneinfo database.
	// For now, return nil and use the hardcoded list above.
	// This will be populated from the timezone database in the container.
	return nil
}

// AdminData handles GET /api/admin
func AdminData(pool *pgxpool.Pool, settingsCache *database.SettingsCache, adminEmail string) http.HandlerFunc {
	settingKeys := []struct{ key, env string }{
		{"support_email", "SUPPORT_EMAIL"}, {"imprint_address", "IMPRINT_ADDRESS"},
		{"imprint_email", "IMPRINT_EMAIL"}, {"enable_legal", "ENABLE_LEGAL"},
		{"ai_provider", "AI_PROVIDER"}, {"ai_key", "AI_KEY"},
		{"ai_endpoint", "AI_ENDPOINT"}, {"ai_model", "AI_MODEL"},
		{"ai_daily_limit", "AI_DAILY_LIMIT"}, {"enable_registration", "ENABLE_REGISTRATION"},
		{"enable_barcode", "ENABLE_BARCODE"},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := pool.Query(r.Context(),
			"SELECT id, email, email_verified, created_at FROM users ORDER BY created_at DESC")
		if err != nil {
			ErrorJSON(w, http.StatusInternalServerError, "Could not load users.")
			return
		}
		defer rows.Close()

		var users []map[string]any
		for rows.Next() {
			var id int
			var email string
			var emailVerified bool
			var createdAt interface{}
			if err := rows.Scan(&id, &email, &emailVerified, &createdAt); err != nil {
				continue
			}
			users = append(users, map[string]any{
				"id":             id,
				"email":          email,
				"email_verified": emailVerified,
				"created_at":     createdAt,
			})
		}
		if users == nil {
			users = []map[string]any{}
		}

		settings := map[string]any{}
		for _, sk := range settingKeys {
			effective := settingsCache.GetEffectiveSetting(r.Context(), sk.key, os.Getenv(sk.env))
			val := ""
			if effective.Value != nil {
				val = *effective.Value
			}
			settings[sk.key] = map[string]any{
				"value":  val,
				"source": effective.Source,
			}
		}

		JSON(w, http.StatusOK, map[string]any{"users": users, "settings": settings})
	}
}

// RegistrationInfo handles GET /api/auth/registration-info (public endpoint)
func RegistrationInfo(settingsCache *database.SettingsCache, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result := settingsCache.GetEffectiveSetting(r.Context(), "enable_registration", cfg.EnableRegistration)
		enabled := true
		if result.Value != nil && *result.Value == "false" {
			enabled = false
		}
		JSON(w, http.StatusOK, map[string]any{"registrationEnabled": enabled})
	}
}

// CleanExpiredTokens runs periodic cleanup of expired tokens.
func CleanExpiredTokens(pool *pgxpool.Pool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, "DELETE FROM password_reset_tokens WHERE expires_at < NOW() OR used = TRUE"); err != nil {
		slog.Error("failed to clean expired password reset tokens", "error", err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM email_verification_tokens WHERE expires_at < NOW() OR used = TRUE"); err != nil {
		slog.Error("failed to clean expired email verification tokens", "error", err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM invite_codes WHERE expires_at IS NOT NULL AND expires_at < NOW() AND used_by IS NULL"); err != nil {
		slog.Error("failed to clean expired invite codes", "error", err)
	}
	if _, err := pool.Exec(ctx, `
		DELETE FROM users
		WHERE email_verified = FALSE
			AND id NOT IN (SELECT DISTINCT user_id FROM email_verification_tokens WHERE used = FALSE)
	`); err != nil {
		slog.Error("failed to clean unverified users", "error", err)
	}
}
