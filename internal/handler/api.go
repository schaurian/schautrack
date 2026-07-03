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

// AuthInfo handles GET /auth/info — returns available auth methods (public, no auth required).
func AuthInfo(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var oidcInfo map[string]string
		if cfg.OIDC != nil {
			oidcInfo = map[string]string{
				"label": cfg.OIDC.Label,
				"slug":  cfg.OIDC.Slug,
				"logo":  cfg.OIDC.LogoURL,
			}
		}
		JSON(w, http.StatusOK, map[string]any{
			"passkeysEnabled": cfg.PasskeysEnabled(),
			"oidc":            oidcInfo,
		})
	}
}

// Me handles GET /api/me
func Me(pool *pgxpool.Pool, adminEmail string, settingsCache *database.SettingsCache, cfg *config.Config) http.HandlerFunc {
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

		var pendingLinkRequests int
		pool.QueryRow(r.Context(),
			"SELECT count(*) FROM account_links WHERE target_id = $1 AND status = 'pending'",
			user.ID).Scan(&pendingLinkRequests)

		passkeyCount, _ := service.CountPasskeys(r.Context(), pool, user.ID)
		oidcCount, _ := service.CountOIDCAccounts(r.Context(), pool, user.ID)
		oidcLinked := oidcCount > 0
		authMethod := session.GetSession(r).GetString("auth_method")

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
				"preferredAiProvider": user.PreferredAIProvider,
				"hasAiKey":           user.AIKey != nil && *user.AIKey != "",
				"hasGlobalAiKey":     hasGlobalAiKey,
				"hasGlobalAiConfig":  hasGlobalAiConfig,
				"aiModel":            user.AIModel,
				"aiDailyLimit":       user.AIDailyLimit,
				"todosEnabled":       user.TodosEnabled,
				"notesEnabled":       user.NotesEnabled,
				"passkeyCount":       passkeyCount,
				"oidcLinked":         oidcLinked,
				"authMethod":         authMethod,
			},
			"isAdmin":             middleware.IsAdmin(user, adminEmail),
			"pendingLinkRequests": pendingLinkRequests,
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

		oidcAccounts, _ := service.ListOIDCAccounts(r.Context(), pool, user.ID)
		authMethod := sess.GetString("auth_method")

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
			"preferredAiProvider": user.PreferredAIProvider,
			"hasAiKey":           hasAiKey,
			"aiKeyLast4":         aiKeyLast4,
			"aiModel":            user.AIModel,
			"aiDailyLimit":       user.AIDailyLimit,
			"todosEnabled":       user.TodosEnabled,
			"notesEnabled":       user.NotesEnabled,
			"hasGlobalAiKey":     hasGlobalAiKey,
			"oidcLinked":         len(oidcAccounts) > 0,
			"authMethod":         authMethod,
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
			"oidcAccounts":     oidcAccounts,
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

		// Build the settings response from the canonical list. Values for
		// secret settings are masked (the saved value never crosses the wire
		// back to the UI — admins re-enter to change).
		settings := map[string]any{}
		for i := range adminSettings {
			s := &adminSettings[i]
			effective := settingsCache.GetEffectiveSetting(r.Context(), s.Key, os.Getenv(s.Env))
			val := ""
			isSet := effective.Value != nil && *effective.Value != ""
			if isSet && !s.Secret {
				val = *effective.Value
			}
			settings[s.Key] = map[string]any{
				"value":     val,
				"source":    effective.Source,
				"section":   s.Section,
				"tier":      s.Tier,
				"secret":    s.Secret,
				"dangerous": s.Dangerous,
				"help":      s.Help,
				"isSet":     isSet, // for secret fields: tells the UI "something is stored" without revealing it
				"envVar":    s.Env,
			}
		}

		// Order metadata so the client can render sections in the canonical order.
		order := make([]string, 0, len(adminSettings))
		for i := range adminSettings {
			order = append(order, adminSettings[i].Key)
		}

		JSON(w, http.StatusOK, map[string]any{
			"users":         users,
			"settings":      settings,
			"settingsOrder": order,
		})
	}
}

// RegistrationInfo handles GET /api/auth/registration-info (public endpoint).
//
// registrationEnabled reports whether sign-up is possible at all (open OR
// invite mode) — the client uses it to decide whether to render the register
// form. inviteRequired is an additive flag telling the client to show the
// invite-code field up front when the server is in invite-only mode.
func RegistrationInfo(settingsCache *database.SettingsCache, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mode := effectiveRegistrationMode(r.Context(), settingsCache, cfg)
		JSON(w, http.StatusOK, map[string]any{
			"registrationEnabled": mode != regModeClosed,
			"inviteRequired":      mode == regModeInvite,
		})
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
	// Reap abandoned password signups whose email was never verified. Federated
	// (OIDC) and passkey-backed accounts must NEVER be deleted here: they
	// authenticate via an external IdP / authenticator and legitimately have no
	// email_verification_tokens row, so without these guards a freshly
	// auto-created OIDC user (whose IdP reports email_verified = false, the
	// stock Keycloak/Authentik/Authelia default) would be purged within minutes
	// of signup, cascading away all of their entries. Exclude any user that has
	// an OIDC account or a registered passkey.
	// The created_at grace period gives a just-registered user time to
	// recover (resend the code, or re-login to get a fresh token) before the
	// account is reaped — previously a single failed/expired verification
	// email could silently cost the account within one cleanup tick.
	if _, err := pool.Exec(ctx, `
		DELETE FROM users
		WHERE email_verified = FALSE
			AND created_at < NOW() - interval '1 hour'
			AND id NOT IN (SELECT DISTINCT user_id FROM email_verification_tokens WHERE used = FALSE)
			AND NOT EXISTS (SELECT 1 FROM user_oidc_accounts o WHERE o.user_id = users.id)
			AND NOT EXISTS (SELECT 1 FROM user_passkeys p WHERE p.user_id = users.id)
	`); err != nil {
		slog.Error("failed to clean unverified users", "error", err)
	}
	// Retention: audit_log and ai_usage otherwise grow unbounded.
	if _, err := pool.Exec(ctx, "DELETE FROM audit_log WHERE created_at < NOW() - interval '90 days'"); err != nil {
		slog.Error("failed to prune old audit log rows", "error", err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM ai_usage WHERE usage_date < CURRENT_DATE - 400"); err != nil {
		slog.Error("failed to prune old ai_usage rows", "error", err)
	}
}
