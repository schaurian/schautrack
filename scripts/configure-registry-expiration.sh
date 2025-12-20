#!/usr/bin/env bash
set -euo pipefail

if [ -z "${REGISTRY_POLICY_TOKEN:-}" ]; then
  echo "REGISTRY_POLICY_TOKEN not set; cannot configure registry expiration policy."
  exit 1
fi

GITLAB_API="${CI_API_V4_URL:-${CI_SERVER_URL%/}/api/v4}"
PROJECT_ID="${CI_PROJECT_ID:?CI_PROJECT_ID is required}"

# Use JSON format for container registry cleanup policy
# High keep_n to accommodate many staging builds + semver releases
echo "Updating container expiration policy for project ${PROJECT_ID}..."

# First, let's see what the error actually is
RESPONSE=$(curl --silent --show-error --write-out "\nHTTP_STATUS:%{http_code}" \
  --header "PRIVATE-TOKEN: ${REGISTRY_POLICY_TOKEN}" \
  --header "Content-Type: application/json" \
  --request PUT \
  --data '{
    "container_expiration_policy_attributes": {
      "enabled": true,
      "name_regex": ".*",
      "name_regex_keep": "latest",
      "keep_n": 40,
      "cadence": "7d"
    }
  }' \
  "${GITLAB_API}/projects/${PROJECT_ID}")

HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_STATUS:/d')

echo "HTTP Status: ${HTTP_STATUS}"
echo "Response: ${BODY}"

if [ "$HTTP_STATUS" -ge 400 ]; then
  echo ""
  echo "Error: Failed to update container expiration policy (HTTP ${HTTP_STATUS})"
  exit 1
fi

echo ""
echo "Container registry expiration policy applied: keep 40 most recent tags (staging + semver), latest protected forever."
