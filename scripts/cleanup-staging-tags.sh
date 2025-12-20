    
#!/usr/bin/env bash
set -euo pipefail

if [ -z "${REGISTRY_POLICY_TOKEN:-}" ]; then
  echo "REGISTRY_POLICY_TOKEN not set; skipping staging tag cleanup."
  exit 0
fi

GITLAB_API="${CI_API_V4_URL:-${CI_SERVER_URL%/}/api/v4}"
PROJECT_ID="${CI_PROJECT_ID:?CI_PROJECT_ID is required}"
# The full image path we want to clean (e.g., my-group/my-project/my-image)
CURRENT_IMAGE="${CI_REGISTRY_IMAGE}"

echo "Fetching staging tags for cleanup for: $CURRENT_IMAGE"

# 1. Get the specific registry repository ID by filtering for the path
# We fetch all repos and use jq to find the one matching our image path
REPO_ID=$(curl --silent --show-error \
  --header "PRIVATE-TOKEN: ${REGISTRY_POLICY_TOKEN}" \
  "${GITLAB_API}/projects/${PROJECT_ID}/registry/repositories" \
  | jq -r --arg PATH "$CURRENT_IMAGE" '.[] | select(.path == $PATH) | .id')

if [ -z "$REPO_ID" ] || [ "$REPO_ID" = "null" ]; then
  echo "No registry repository found matching path: $CURRENT_IMAGE"
  exit 0
fi

echo "Using registry repository ID: $REPO_ID"

# 2. Get all tags
# NOTE: To safely handle >100 tags, we'd need a loop. 
# For simplicity, this still grabs 100, but sorts by 'updated_desc' via API if possible
# or assumes the input is large enough.
ALL_TAGS=$(curl --silent --show-error \
  --header "PRIVATE-TOKEN: ${REGISTRY_POLICY_TOKEN}" \
  "${GITLAB_API}/projects/${PROJECT_ID}/registry/repositories/${REPO_ID}/tags?per_page=100")

# 3. Filter and Sort
# We assume format staging-{number} or similar. 
# We explicitly filter for non-empty names.
STAGING_TAGS=$(echo "$ALL_TAGS" | jq -r '.[] | select(.name | startswith("staging-")) | .name' | sort -t'-' -k2 -n -r)

# Count staging tags
# usage of grep -c can fail with set -e if 0 lines found, hence || true
TAG_COUNT=$(echo "$STAGING_TAGS" | grep -c "staging-" || true)
echo "Found ${TAG_COUNT} staging tags"

KEEP_COUNT=10

if [ "$TAG_COUNT" -le "$KEEP_COUNT" ]; then
  echo "Only ${TAG_COUNT} staging tags found, keeping all (threshold: ${KEEP_COUNT})"
  exit 0
fi

DELETE_COUNT=$((TAG_COUNT - KEEP_COUNT))
echo "Deleting ${DELETE_COUNT} old staging tags (keeping ${KEEP_COUNT} most recent)..."

DELETED=0
SKIPPED=0

# 4. FIX: Use Process Substitution (< <(...)) to avoid subshell variable loss
while read -r tag; do
  if [ -n "$tag" ]; then
    echo "Deleting tag: $tag"
    HTTP_CODE=$(curl --silent --show-error --write-out "%{http_code}" --output /dev/null \
      --header "PRIVATE-TOKEN: ${REGISTRY_POLICY_TOKEN}" \
      --request DELETE \
      "${GITLAB_API}/projects/${PROJECT_ID}/registry/repositories/${REPO_ID}/tags/${tag}")

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ] || [ "$HTTP_CODE" = "202" ]; then
      DELETED=$((DELETED + 1))
    else
      echo "Failed to delete $tag (HTTP $HTTP_CODE)"
      SKIPPED=$((SKIPPED + 1))
    fi
  fi
done < <(echo "$STAGING_TAGS" | tail -n +$((KEEP_COUNT + 1)))

echo "Cleanup complete: ${DELETED} deleted, ${SKIPPED} failed"

if [ "$SKIPPED" -gt 0 ]; then
  exit 1
fi