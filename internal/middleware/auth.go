package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/model"
	"schautrack/internal/session"
)

type contextKey string

const userContextKey contextKey = "currentUser"

// GetUserByID loads a user from the database.
func GetUserByID(ctx context.Context, pool *pgxpool.Pool, id int) (*model.User, error) {
	u := &model.User{}
	var macrosEnabled, macroGoals []byte
	err := pool.QueryRow(ctx, `
		SELECT id, email, daily_goal, totp_enabled, totp_secret, timezone, weight_unit, timezone_manual,
			preferred_ai_provider, ai_key, ai_endpoint, ai_model, ai_daily_limit, ai_key_last4,
			macros_enabled, macro_goals, goal_threshold, todos_enabled, notes_enabled
		FROM users WHERE id = $1`, id,
	).Scan(
		&u.ID, &u.Email, &u.DailyGoal, &u.TOTPEnabled, &u.TOTPSecret, &u.Timezone, &u.WeightUnit, &u.TimezoneManual,
		&u.PreferredAIProvider, &u.AIKey, &u.AIEndpoint, &u.AIModel, &u.AIDailyLimit, &u.AIKeyLast4,
		&macrosEnabled, &macroGoals, &u.GoalThreshold, &u.TodosEnabled, &u.NotesEnabled,
	)
	if err != nil {
		return nil, err
	}
	u.MacrosEnabled = macrosEnabled
	u.MacroGoals = macroGoals
	return u, nil
}

// IsAdmin checks if a user is the admin.
func IsAdmin(user *model.User, adminEmail string) bool {
	if adminEmail == "" || user == nil {
		return false
	}
	return strings.EqualFold(user.Email, adminEmail)
}

// AttachUser loads the current user from the session.
func AttachUser(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := session.GetSession(r)
			if sess == nil {
				next.ServeHTTP(w, r)
				return
			}

			userID, ok := sess.UserID()
			if !ok {
				next.ServeHTTP(w, r)
				return
			}

			user, err := GetUserByID(r.Context(), pool, userID)
			if err != nil {
				log.Printf("Failed to load user from session: %v", err)
				next.ServeHTTP(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireLogin returns 401 if no user is authenticated.
func RequireLogin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if GetCurrentUser(r) == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"error": "Authentication required"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireLocalAuth returns 403 if the current session was started via OIDC.
// Blocks management of local auth surface (password, 2FA, passkeys, email,
// OIDC unlink) so federated users can only manage auth at their IdP.
func RequireLocalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := session.GetSession(r)
		if sess != nil && sess.GetString("auth_method") == "oidc" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"error": "Log in with a password to change authentication settings."})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin returns 403 if user is not admin.
func RequireAdmin(adminEmail string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetCurrentUser(r)
			if user == nil || !IsAdmin(user, adminEmail) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]any{"error": "Forbidden"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GetCurrentUser retrieves the user from request context.
func GetCurrentUser(r *http.Request) *model.User {
	user, _ := r.Context().Value(userContextKey).(*model.User)
	return user
}
