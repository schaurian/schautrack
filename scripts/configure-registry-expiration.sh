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
curl --fail --silent --show-error \
  --header "PRIVATE-TOKEN: ${REGISTRY_POLICY_TOKEN}" \
  --header "Content-Type: application/json" \
  --request PUT \
  --data '{
    "container_expiration_policy_attributes": {
      "enabled": true,
      "name_regex": "^staging-|^v[0-9]",
      "name_regex_keep": "^latest$",
      "keep_n": 40,
      "cadence": "7d"
    }
  }' \
  "${GITLAB_API}/projects/${PROJECT_ID}"

echo ""
echo "Container registry expiration policy applied: keep 40 most recent tags (staging + semver), latest protected forever."
