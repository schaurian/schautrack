#!/usr/bin/env bash
set -euo pipefail

if [ -z "${REGISTRY_POLICY_TOKEN:-}" ]; then
  echo "REGISTRY_POLICY_TOKEN not set; skipping staging tag cleanup."
  exit 0
fi

GITLAB_API="${CI_API_V4_URL:-${CI_SERVER_URL%/}/api/v4}"
PROJECT_ID="${CI_PROJECT_ID:?CI_PROJECT_ID is required}"
REGISTRY_ID="${CI_REGISTRY_IMAGE##*/}"

echo "Fetching staging tags for cleanup..."

# Get the registry repository ID
REPOS=$(curl --silent --show-error \
  --header "PRIVATE-TOKEN: ${REGISTRY_POLICY_TOKEN}" \
  "${GITLAB_API}/projects/${PROJECT_ID}/registry/repositories")

echo "DEBUG: Registry repositories response: $REPOS"

REPO_ID=$(echo "$REPOS" | jq -r '.[0].id')

if [ -z "$REPO_ID" ] || [ "$REPO_ID" = "null" ]; then
  echo "No registry repository found"
  exit 0
fi

echo "Using registry repository ID: $REPO_ID"

# Get all staging tags, sorted by created date
STAGING_TAGS=$(curl --silent --show-error \
  --header "PRIVATE-TOKEN: ${REGISTRY_POLICY_TOKEN}" \
  "${GITLAB_API}/projects/${PROJECT_ID}/registry/repositories/${REPO_ID}/tags?per_page=100" | \
  jq -r '.[] | select(.name | startswith("staging-")) | .name' | \
  sort -t'-' -k2 -n -r)

# Count staging tags
TAG_COUNT=$(echo "$STAGING_TAGS" | grep -c "staging-" || true)
echo "Found ${TAG_COUNT} staging tags"

# Keep the 10 most recent staging tags, delete the rest
KEEP_COUNT=10
if [ "$TAG_COUNT" -le "$KEEP_COUNT" ]; then
  echo "Only ${TAG_COUNT} staging tags found, keeping all (threshold: ${KEEP_COUNT})"
  exit 0
fi

# Skip the first KEEP_COUNT tags and delete the rest
DELETE_COUNT=$((TAG_COUNT - KEEP_COUNT))
echo "Deleting ${DELETE_COUNT} old staging tags (keeping ${KEEP_COUNT} most recent)..."

DELETED=0
SKIPPED=0
echo "$STAGING_TAGS" | tail -n +$((KEEP_COUNT + 1)) | while read -r tag; do
  if [ -n "$tag" ]; then
    echo "Deleting tag: $tag"
    HTTP_CODE=$(curl --silent --show-error --write-out "%{http_code}" --output /dev/null \
      --header "PRIVATE-TOKEN: ${REGISTRY_POLICY_TOKEN}" \
      --request DELETE \
      "${GITLAB_API}/projects/${PROJECT_ID}/registry/repositories/${REPO_ID}/tags/${tag}")

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
      DELETED=$((DELETED + 1))
    else
      echo "Failed to delete $tag (HTTP $HTTP_CODE)"
      SKIPPED=$((SKIPPED + 1))
    fi
  fi
done

echo "Cleanup complete: ${DELETED} deleted, ${SKIPPED} failed"
