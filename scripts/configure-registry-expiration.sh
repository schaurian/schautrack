#!/usr/bin/env bash
set -euo pipefail

if [ -z "${REGISTRY_POLICY_TOKEN:-}" ]; then
  echo "REGISTRY_POLICY_TOKEN not set; cannot configure registry expiration policy."
  exit 1
fi

GITLAB_API="${CI_API_V4_URL:-${CI_SERVER_URL%/}/api/v4}"
PROJECT_ID="${CI_PROJECT_ID:?CI_PROJECT_ID is required}"

curl --fail --header "PRIVATE-TOKEN: ${REGISTRY_POLICY_TOKEN}" \
  --request PUT \
  --data "enabled=true" \
  --data "name_regex=.*" \
  --data "name_regex_keep=^latest$|^v[0-9]" \
  --data "keep_n=15" \
  --data "older_than=30d" \
  --data "cadence=7d" \
  "${GITLAB_API}/projects/${PROJECT_ID}/registry/expiration_policies"

echo "Container registry expiration policy applied: keep semver + latest, retain 15 tags, delete older than 30d on a 7d cadence."
