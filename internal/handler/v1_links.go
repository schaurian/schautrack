package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"schautrack/internal/apierr"
	"schautrack/internal/middleware"
	"schautrack/internal/model"
	"schautrack/internal/service"
)

// v1Link is a linked account, from the caller's point of view.
type v1Link struct {
	// UserID is what to pass as ?user= on a read endpoint.
	UserID int     `json:"user_id"`
	Email  string  `json:"email"`
	Label  *string `json:"label"`

	// SharesWithMe lists the categories this account shares WITH the caller —
	// the only ones ?user= will actually serve. SharesToThem is what the
	// caller shares back, included so a client can render both directions
	// without a second call.
	SharesWithMe map[string]bool `json:"shares_with_me"`
	SharesToThem map[string]bool `json:"shares_to_them"`

	// Timezone is the linked account's zone. Their entry timestamps are in it,
	// not the caller's — you want to know when THEY ate, not what time it was
	// where you are.
	Timezone string `json:"timezone"`
}

// ListLinksV1 handles GET /api/v1/links.
func (h *V1Handler) ListLinksV1(w http.ResponseWriter, r *http.Request) {
	user := v1User(r)

	rows, err := h.Pool.Query(r.Context(), `
		SELECT
			CASE WHEN l.requester_id = $1 THEN l.target_id ELSE l.requester_id END AS other_id,
			u.email,
			CASE WHEN l.requester_id = $1 THEN l.requester_label ELSE l.target_label END AS label,
			-- What the OTHER side shares with the caller, and vice versa.
			CASE WHEN l.requester_id = $1 THEN l.target_shares ELSE l.requester_shares END AS shares_with_me,
			CASE WHEN l.requester_id = $1 THEN l.requester_shares ELSE l.target_shares END AS shares_to_them,
			COALESCE(u.timezone, 'UTC')
		FROM account_links l
		JOIN users u ON u.id = CASE WHEN l.requester_id = $1 THEN l.target_id ELSE l.requester_id END
		WHERE l.status = 'accepted' AND (l.requester_id = $1 OR l.target_id = $1)
		ORDER BY other_id`, user.ID)
	if err != nil {
		apierr.Write(w, r, dbFail("list links", err))
		return
	}
	defer rows.Close()

	out := []v1Link{}
	for rows.Next() {
		var l v1Link
		var withMe, toThem []byte
		if err := rows.Scan(&l.UserID, &l.Email, &l.Label, &withMe, &toThem, &l.Timezone); err != nil {
			apierr.Write(w, r, dbFail("scan link", err))
			return
		}
		l.SharesWithMe = decodeShareFlags(withMe)
		l.SharesToThem = decodeShareFlags(toThem)
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		apierr.Write(w, r, dbFail("iterate links", err))
		return
	}
	writeV1(w, http.StatusOK, v1List[v1Link]{Data: out})
}

// decodeShareFlags normalises a JSONB share map to exactly the known
// categories, so a response never advertises a category the server does not
// understand and never omits one it does.
func decodeShareFlags(raw []byte) map[string]bool {
	out := make(map[string]bool, len(service.ShareCategories))
	parsed := map[string]bool{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &parsed)
	}
	for _, c := range service.ShareCategories {
		out[c] = parsed[c]
	}
	return out
}

// target is the account a read request is about: the caller, or a linked
// account named by ?user=.
type target struct {
	User *model.User
	// IsSelf is false when reading someone else's shared data, which changes
	// which timezone timestamps are rendered in.
	IsSelf bool
}

// resolveTarget works out whose data a read endpoint should return.
//
// Without ?user= it is always the caller. With it, three things must all hold:
// the token carries links:read, the two accounts are linked, and the other
// account shares this category. Any failure is 403 — never 404, which would
// otherwise let a caller probe which user IDs exist by watching the status
// change.
//
// Shared data is strictly read-only. No write endpoint calls this, so there is
// no path by which a token can modify a linked account's data.
func (h *V1Handler) resolveTarget(r *http.Request, category string) (target, *apierr.Problem) {
	user := v1User(r)
	raw := strings.TrimSpace(r.URL.Query().Get("user"))
	if raw == "" {
		return target{User: user, IsSelf: true}, nil
	}

	id, err := strconv.Atoi(raw)
	if err != nil || id <= 0 {
		return target{}, apierr.BadRequest(`"user" must be the user_id of a linked account, from GET /api/v1/links.`)
	}
	if id == user.ID {
		return target{User: user, IsSelf: true}, nil
	}

	token := middleware.GetAPIToken(r)
	if token == nil || !service.ScopeSatisfies(token.Scopes, service.ScopeLinksRead) {
		return target{}, apierr.InsufficientScope(service.ScopeLinksRead)
	}

	var shared bool
	err = h.Pool.QueryRow(r.Context(), `
		SELECT COALESCE(
			(CASE WHEN requester_id = $2 THEN requester_shares ELSE target_shares END ->> $3)::boolean,
			false)
		FROM account_links
		WHERE status = 'accepted'
			AND ((requester_id = $1 AND target_id = $2) OR (requester_id = $2 AND target_id = $1))`,
		user.ID, id, category).Scan(&shared)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return target{}, apierr.Forbidden("That account is not linked to yours.")
		}
		return target{}, dbFail("check link sharing", err)
	}
	if !shared {
		return target{}, apierr.Forbidden(
			"That account does not share " + category + " with you.")
	}

	other, err := middleware.GetUserByID(r.Context(), h.Pool, id)
	if err != nil {
		return target{}, dbFail("load linked user", err)
	}
	return target{User: other, IsSelf: false}, nil
}

// tz returns the timezone a target's timestamps should be rendered in.
//
// Your own entries render in your zone. A linked account's render in THEIRS —
// so you see when they actually ate, not what the clock said where you are.
// This mirrors what the app does and is the whole reason Link carries timezone.
func (t target) tz() string {
	z := t.User.GetTimezone()
	if z == "" {
		return "UTC"
	}
	return z
}
