package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/model"
)

type linkContextKey string

const (
	targetUserIDKey linkContextKey = "targetUserID"
	targetUserKey   linkContextKey = "targetUser"
)

// RequireLinkAuth checks the ?user= parameter and verifies linking.
func RequireLinkAuth(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			currentUser := GetCurrentUser(r)
			if currentUser == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]any{"error": "Authentication required"})
				return
			}

			targetUserID := currentUser.ID
			if userParam := r.URL.Query().Get("user"); userParam != "" {
				if id, err := strconv.Atoi(userParam); err == nil {
					targetUserID = id
				}
			}

			var targetUser *model.User

			if targetUserID != currentUser.ID {
				// Load target user
				var err error
				targetUser, err = GetUserByID(r.Context(), pool, targetUserID)
				if err != nil || targetUser == nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "Not authorized"})
					return
				}

				// Check if linked
				var exists bool
				err = pool.QueryRow(r.Context(), `
					SELECT EXISTS(
						SELECT 1 FROM account_links
						WHERE status = 'accepted'
							AND ((requester_id = $1 AND target_id = $2) OR (requester_id = $2 AND target_id = $1))
					)`, currentUser.ID, targetUserID).Scan(&exists)
				if err != nil {
					log.Printf("Link auth check failed: %v", err)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "Authorization check failed"})
					return
				}
				if !exists {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "Not authorized"})
					return
				}
			} else {
				targetUser = currentUser
			}

			ctx := context.WithValue(r.Context(), targetUserIDKey, targetUserID)
			ctx = context.WithValue(ctx, targetUserKey, targetUser)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetTargetUserID returns the target user ID from context.
func GetTargetUserID(r *http.Request) int {
	id, _ := r.Context().Value(targetUserIDKey).(int)
	return id
}

// GetTargetUser returns the target user from context.
func GetTargetUser(r *http.Request) *model.User {
	user, _ := r.Context().Value(targetUserKey).(*model.User)
	return user
}
