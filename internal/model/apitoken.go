package model

import "time"

// APIToken is a personal access token for the public HTTP API (/api/v1).
//
// The raw secret is returned exactly once, at creation. Only its SHA-256
// digest is persisted, so a database disclosure yields no usable credential.
// Prefix is a short, non-secret fragment kept solely so the UI can show
// "stk_a1b2c3…" next to each token and the user can tell them apart.
type APIToken struct {
	ID     int      `json:"id"`
	UserID int      `json:"-"`
	Name   string   `json:"name"`
	Prefix string   `json:"prefix"`
	Scopes []string `json:"scopes"`

	// ExpiresAt nil means the token never expires.
	ExpiresAt *time.Time `json:"expires_at"`

	// LastUsedAt is written lazily (see service.TouchAPIToken) — it is an
	// "is this still in use?" signal for the user, not an audit log.
	LastUsedAt *time.Time `json:"last_used_at"`

	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at"`
}

// Active reports whether the token may still authenticate a request.
func (t *APIToken) Active(now time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	if t.ExpiresAt != nil && !now.Before(*t.ExpiresAt) {
		return false
	}
	return true
}
