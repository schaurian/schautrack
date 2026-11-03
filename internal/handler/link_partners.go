package handler

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type rowQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// acceptedLinkPartners returns the users userID has an accepted link with.
//
// Read BEFORE an account is deleted: the delete cascades the links away, and
// afterwards there is no record of whose SSE link cache still names the
// account. Those caches must be invalidated, or a partner's activity events
// keep going to the deleted account's still-open streams for up to the TTL.
func acceptedLinkPartners(ctx context.Context, q rowQuerier, userID int) ([]int, error) {
	rows, err := q.Query(ctx, `
		SELECT CASE WHEN requester_id = $1 THEN target_id ELSE requester_id END
		FROM account_links
		WHERE status = 'accepted' AND (requester_id = $1 OR target_id = $1)`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int])
}
