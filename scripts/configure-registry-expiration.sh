#!/usr/bin/env bash
set -euo pipefail

if [ -z "${REGISTRY_POLICY_TOKEN:-}" ]; then
  echo "REGISTRY_POLICY_TOKEN not set; cannot configure registry expiration policy."
  exit 1
fi

GITLAB_API="${CI_API_V4_URL:-${CI_SERVER_URL%/}/api/v4}"
PROJECT_ID="${CI_PROJECT_ID:?CI_PROJECT_ID is required}"

# Use form data instead of JSON for container registry cleanup policy
curl --fail --header "PRIVATE-TOKEN: ${REGISTRY_POLICY_TOKEN}" \
  --request PUT \
  --data "container_expiration_policy_attributes[enabled]=true" \
  --data "container_expiration_policy_attributes[name_regex]=.*" \
  --data "container_expiration_policy_attributes[name_regex_keep]=^latest\$|^v[0-9]" \
  --data "container_expiration_policy_attributes[keep_n]=15" \
  --data "container_expiration_policy_attributes[older_than]=30d" \
  --data "container_expiration_policy_attributes[cadence]=7d" \
  "${GITLAB_API}/projects/${PROJECT_ID}"

echo "Container registry expiration policy applied: keep semver + latest, retain 15 tags, delete older than 30d on a 7d cadence."
