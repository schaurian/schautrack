package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/service"
	"schautrack/internal/session"
)

// RequireStepUp gates handlers behind fresh primary auth. If the session has
// completed primary auth (login, passkey, OIDC, …) within session.StepUpTTL,
// the request passes through. Otherwise it returns 403 with a structured body
// listing the elevation methods available to this user — the client uses that
// to render an appropriate step-up modal and retries the original request on
// success.
func RequireStepUp(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := session.GetSession(r)
			if sess != nil && sess.HasRecentStepUp() {
				next.ServeHTTP(w, r)
				return
			}

			user := GetCurrentUser(r)
			hasPass := false
			passkeyCount := 0
			totpEnabled := false
			if user != nil {
				hasPass, _ = service.HasPassword(r.Context(), pool, user.ID)
				passkeyCount, _ = service.CountPasskeys(r.Context(), pool, user.ID)
				totpEnabled = user.TOTPEnabled
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(stepUpResponse(hasPass, passkeyCount, totpEnabled))
		})
	}
}

// stepUpResponse computes the 403 body. Split out so the policy is testable
// without a database.
func stepUpResponse(hasPassword bool, passkeyCount int, totpEnabled bool) map[string]any {
	methods := []string{}
	if hasPassword {
		methods = append(methods, "password")
	}
	if passkeyCount > 0 {
		methods = append(methods, "passkey")
	}
	return map[string]any{
		"error":         "step_up_required",
		"requireStepUp": true,
		"methods":       methods,
		"totpRequired":  hasPassword && totpEnabled,
	}
}
