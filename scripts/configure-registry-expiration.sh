#!/usr/bin/env bash
set -euo pipefail

if [ -z "${REGISTRY_POLICY_TOKEN:-}" ]; then
  echo "REGISTRY_POLICY_TOKEN not set; cannot configure registry expiration policy."
  exit 1
fi

GITLAB_API="${CI_API_V4_URL:-${CI_SERVER_URL%/}/api/v4}"
PROJECT_ID="${CI_PROJECT_ID:?CI_PROJECT_ID is required}"

# Use the correct API endpoint for container registry cleanup policy
curl --fail --header "PRIVATE-TOKEN: ${REGISTRY_POLICY_TOKEN}" \
  --header "Content-Type: application/json" \
  --request PUT \
  --data '{
    "container_expiration_policy_attributes": {
      "enabled": true,
      "name_regex": ".*",
      "name_regex_keep": "^latest$|^v[0-9]",
      "keep_n": 15,
      "older_than": "30d",
      "cadence": "7d"
    }
  }' \
  "${GITLAB_API}/projects/${PROJECT_ID}"

echo "Container registry expiration policy applied: keep semver + latest, retain 15 tags, delete older than 30d on a 7d cadence."
