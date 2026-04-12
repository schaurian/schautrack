package service

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
)

type LinkUser struct {
	LinkID        int             `json:"linkId"`
	UserID        int             `json:"userId"`
	Label         *string         `json:"label"`
	Email         string          `json:"email"`
	DailyGoal     *int            `json:"daily_goal"`
	MacroGoals    json.RawMessage `json:"macro_goals"`
	Timezone      string          `json:"timezone"`
	GoalThreshold int             `json:"goal_threshold"`
	MacrosEnabled json.RawMessage `json:"macros_enabled"`
}

func (lu LinkUser) AsMacroUser() MacroUser {
	me := make(map[string]any)
	mg := make(map[string]any)
	json.Unmarshal(lu.MacrosEnabled, &me)
	json.Unmarshal(lu.MacroGoals, &mg)
	return MacroUser{MacrosEnabled: me, MacroGoals: mg, DailyGoal: lu.DailyGoal, GoalThreshold: lu.GoalThreshold}
}

type LinkRequest struct {
	ID        int    `json:"id"`
	Email     string `json:"email"`
	CreatedAt any    `json:"created_at"`
}

type LinkState struct {
	Incoming []LinkRequest `json:"incoming"`
	Outgoing []LinkRequest `json:"outgoing"`
}

func CountAcceptedLinks(ctx context.Context, pool *pgxpool.Pool, userID int) (int, error) {
	var count int
	err := pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM account_links WHERE status = 'accepted' AND (requester_id = $1 OR target_id = $1)",
		userID).Scan(&count)
	return count, err
}

func GetLinkRequests(ctx context.Context, pool *pgxpool.Pool, userID int) (LinkState, error) {
	state := LinkState{Incoming: []LinkRequest{}, Outgoing: []LinkRequest{}}

	rows, err := pool.Query(ctx, `
		SELECT al.id, u.email, al.created_at
		FROM account_links al JOIN users u ON u.id = al.requester_id
		WHERE al.target_id = $1 AND al.status = 'pending'
		ORDER BY al.created_at DESC`, userID)
	if err != nil {
		return state, err
	}
	defer rows.Close()
	for rows.Next() {
		var r LinkRequest
		if err := rows.Scan(&r.ID, &r.Email, &r.CreatedAt); err == nil {
			state.Incoming = append(state.Incoming, r)
		}
	}

	rows2, err := pool.Query(ctx, `
		SELECT al.id, u.email, al.created_at
		FROM account_links al JOIN users u ON u.id = al.target_id
		WHERE al.requester_id = $1 AND al.status = 'pending'
		ORDER BY al.created_at DESC`, userID)
	if err != nil {
		return state, err
	}
	defer rows2.Close()
	for rows2.Next() {
		var r LinkRequest
		if err := rows2.Scan(&r.ID, &r.Email, &r.CreatedAt); err == nil {
			state.Outgoing = append(state.Outgoing, r)
		}
	}

	return state, nil
}

func GetAcceptedLinkUsers(ctx context.Context, pool *pgxpool.Pool, userID int) ([]LinkUser, error) {
	rows, err := pool.Query(ctx, `
		SELECT al.id AS link_id,
			CASE WHEN al.requester_id = $1 THEN al.requester_label ELSE al.target_label END AS label,
			CASE WHEN al.requester_id = $1 THEN al.target_id ELSE al.requester_id END AS other_id,
			u.email AS other_email,
			u.daily_goal AS other_daily_goal,
			u.macro_goals AS other_macro_goals,
			u.timezone AS other_timezone,
			u.goal_threshold AS other_goal_threshold,
			u.macros_enabled AS other_macros_enabled
		FROM account_links al
		JOIN users u ON u.id = CASE WHEN al.requester_id = $1 THEN al.target_id ELSE al.requester_id END
		WHERE al.status = 'accepted' AND ($1 = al.requester_id OR $1 = al.target_id)
		ORDER BY al.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []LinkUser
	for rows.Next() {
		var lu LinkUser
		var timezone *string
		var macroGoals, macrosEnabled []byte
		if err := rows.Scan(&lu.LinkID, &lu.Label, &lu.UserID, &lu.Email,
			&lu.DailyGoal, &macroGoals, &timezone, &lu.GoalThreshold, &macrosEnabled); err != nil {
			continue
		}
		lu.Timezone = "UTC"
		if timezone != nil {
			lu.Timezone = *timezone
		}
		if macroGoals != nil {
			lu.MacroGoals = macroGoals
		} else {
			lu.MacroGoals = json.RawMessage(`{}`)
		}
		if macrosEnabled != nil {
			lu.MacrosEnabled = macrosEnabled
		} else {
			lu.MacrosEnabled = json.RawMessage(`{}`)
		}
		result = append(result, lu)
	}
	if result == nil {
		result = []LinkUser{}
	}
	return result, nil
}
