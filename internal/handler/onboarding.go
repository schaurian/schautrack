package handler

import (
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"schautrack/internal/middleware"
)

type OnboardingHandler struct {
	Pool *pgxpool.Pool
}

// Complete handles POST /api/onboarding/complete — the welcome tour was
// dismissed, so it must not open by itself again.
//
// The WHERE clause keeps the FIRST completion timestamp: replaying the tour
// from Settings ends in this same call, and overwriting the original date
// would turn a "when did this account get onboarded" record into "when did
// they last watch the tour".
func (h *OnboardingHandler) Complete(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetCurrentUser(r)
	if _, err := h.Pool.Exec(r.Context(),
		"UPDATE users SET onboarding_completed_at = NOW() WHERE id = $1 AND onboarding_completed_at IS NULL",
		user.ID); err != nil {
		slog.Error("failed to mark onboarding complete", "error", err)
		ErrorJSON(w, http.StatusInternalServerError, "Failed to save.")
		return
	}
	OkJSON(w)
}
