package handler

import "schautrack/internal/service"

// savedFoodVisibleTo is the one predicate deciding which saved foods a caller
// may read: their own, plus those owned by someone who shares the savedfoods
// category TOWARD them over an accepted link.
//
// One definition, used by the app list, the app track, and their v1 twins. Four
// copies of this is how the surfaces drift, and a drift here is an
// authorization bug rather than an inconsistency — savedFoodRank exists for the
// same reason after the app and the API disagreed on a tiebreaker.
//
// $1 is the caller. The parameter is referenced twice, which is deliberate:
//
//	account_links stores ONE row per link with two direction-specific share
//	maps. requester_shares is what the requester exposes, target_shares what
//	the target exposes. So "does the OWNER share with ME" reads the map
//	belonging to the owner's side, which flips depending on which side of the
//	row the owner sits on. Reading the other branch inverts the check into
//	"do I share with them", exposing foods the owner never offered — and every
//	test asserting that sharing works would still pass, because in a symmetric
//	fixture both directions are on. That is why the tests include a case where
//	only one direction is enabled.
const savedFoodVisibleTo = `(
	saved_foods.user_id = $1
	OR EXISTS (
		SELECT 1 FROM account_links al
		WHERE al.status = 'accepted'
		  AND (
		    (al.requester_id = saved_foods.user_id AND al.target_id = $1
		       AND COALESCE((al.requester_shares ->> '` + service.ShareSavedFoods + `')::boolean, false))
		    OR
		    (al.target_id = saved_foods.user_id AND al.requester_id = $1
		       AND COALESCE((al.target_shares ->> '` + service.ShareSavedFoods + `')::boolean, false))
		  )
	)
)`

// savedFoodOwnerLabel renders whose food a row is, for the client to attribute
// a borrowed chip. NULL for the caller's own, otherwise the label the caller
// gave that link (falling back to the owner's email local-part, which is what
// the links UI shows when no label is set).
const savedFoodOwnerLabel = `CASE WHEN saved_foods.user_id = $1 THEN NULL ELSE (
	SELECT COALESCE(
		NULLIF(CASE WHEN al.requester_id = $1 THEN al.requester_label ELSE al.target_label END, ''),
		split_part(u.email, '@', 1))
	FROM account_links al
	JOIN users u ON u.id = saved_foods.user_id
	WHERE al.status = 'accepted'
	  AND ((al.requester_id = saved_foods.user_id AND al.target_id = $1)
	    OR (al.target_id = saved_foods.user_id AND al.requester_id = $1))
	LIMIT 1
) END`
