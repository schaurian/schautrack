#!/bin/sh
# Property-test /api/v1 against its own OpenAPI document with Schemathesis.
#
#   npm run test:contract          -> brings the stack up, runs, tears it down
#   KEEP_STACK=1 npm run test:contract
#   API_CONTRACT_BASE=... TOKEN=... sh scripts/api-contract-test.sh   (bring your own)
#
# Why this exists as a separate suite:
#
# The Go tests assert the endpoints this repo thought to write a test for, with
# the payloads it thought to send. `TestV1RoutesMatchSpec` already guarantees
# the route table and api/openapi.json describe the same set of endpoints — but
# agreeing on which endpoints exist says nothing about whether the *responses*
# match the schemas the document promises. That gap is where a client written
# against the published spec breaks.
#
# Schemathesis reads the committed document and generates requests from it:
# every parameter at its boundaries, every declared type violated in turn,
# every optional field present and absent. It then checks each response against
# the schema the document declares for that status code. What it reliably finds
# is the class no hand-written test covers — a 500 on input the spec says is
# legal, a response shape that drifted from its schema, a status code the
# document never mentions.
#
# It runs against the compose.test.yml stack rather than a Go httptest server
# because the contract belongs to the deployed thing: middleware ordering, the
# body-size caps, the rate limiters and the problem+json error writer are all
# part of what a client sees, and none of them are exercised by calling a
# handler directly.

set -e
cd "$(dirname "$0")/.." || exit 1

COMPOSE="docker compose -f compose.test.yml"
BASE="${API_CONTRACT_BASE:-http://localhost:3001}"
DB_USER="${POSTGRES_USER:-schautrack}"
DB_NAME="${POSTGRES_DB:-schautrack}"
OWN_STACK=0

teardown() {
  if [ "$OWN_STACK" = "1" ] && [ -z "$KEEP_STACK" ]; then
    echo "==> tearing down the test stack"
    $COMPOSE down || true
  fi
}
trap teardown EXIT INT TERM

if [ -z "$TOKEN" ]; then
  if ! curl -fsS "$BASE/api/health" >/dev/null 2>&1; then
    echo "==> starting the test stack"
    $COMPOSE down -v >/dev/null 2>&1 || true
    $COMPOSE up -d --build --wait
    OWN_STACK=1
  fi

  DB_CONTAINER=$($COMPOSE ps -q db)
  [ -n "$DB_CONTAINER" ] || { echo "could not find the db container" >&2; exit 1; }

  psql() { docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -tA; }

  # Mint the token here rather than through the UI. Token creation is
  # step-up gated on purpose (a token that could mint another token would turn
  # one leaked read-only token into a permanent full-scope one), so driving it
  # over HTTP means a login plus a step-up dance for no benefit — the thing
  # under test is /api/v1, not the minting flow, which api-tokens.spec.ts
  # already covers.
  #
  # The digest is a bare SHA-256 of the whole raw token, matching
  # service.HashAPIToken. If that ever changes, this seeds an unusable token
  # and every request 401s — loudly, not silently.
  SECRET=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')
  TOKEN="stk_${SECRET}"
  HASH=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)
  PREFIX="stk_$(printf '%s' "$SECRET" | cut -c1-6)"

  # Every grantable scope: the point is to reach every endpoint, so a 403 is
  # never the reason coverage stopped. Scopes themselves are covered by the Go
  # tests.
  SCOPES="entries:read,entries:write,weight:read,weight:write,todos:read,todos:write,foods:read,foods:write,notes:read,notes:write,plan:read,links:read,settings:read,settings:write"

  echo "==> seeding a contract-test user and token"
  psql <<SQL >/dev/null
INSERT INTO users (email, password_hash, email_verified)
VALUES ('contract@test.com', 'x', true)
ON CONFLICT (email) DO NOTHING;
DELETE FROM api_tokens WHERE name = 'schemathesis';
INSERT INTO api_tokens (user_id, name, token_hash, prefix, scopes)
SELECT id, 'schemathesis', decode('${HASH}', 'hex'), '${PREFIX}', string_to_array('${SCOPES}', ',')
FROM users WHERE email = 'contract@test.com';
SQL
fi

# CHECKS defaults to the one that is green today, so this can gate from its
# first commit instead of being a job everyone learns to ignore.
#
# not_a_server_error is also the check that matters most: a 500 on input the
# document says is legal is unambiguously a bug, whereas the others below are
# mostly the *document* being wrong, which is a different (real, but lower
# severity) problem.
#
# Still failing, and worth turning on one at a time as the spec is tightened —
# run with `--checks all` to see them:
#
#   negative_data_rejection      3 cases the API accepts that the schema forbids
#   positive_data_acceptance    28 cases the schema permits that the API rejects
#                                  (validation is stricter than documented —
#                                  e.g. date and note constraints)
#   content_type_conformance     2 responses whose Content-Type is undeclared
#   unsupported_method          14 operations that 405 correctly but do not say
#                                  so in the document
#
# None of those is a crash; all of them are a client being told something the
# server does not actually do.
CHECKS="${CHECKS:-not_a_server_error}"

# ai:estimate is deliberately NOT granted above. Every call to it spends real
# money with the operator's AI provider, and a fuzzer is exactly the caller you
# do not want holding that scope. The endpoint is excluded below to match.
echo "==> running Schemathesis against $BASE/api/v1 (checks: $CHECKS)"
exec uvx --from 'schemathesis>=4,<5' schemathesis run \
  "$BASE/api/v1/openapi.json" \
  --url "$BASE/api/v1" \
  --header "Authorization: Bearer $TOKEN" \
  --exclude-path-regex '/ai/' \
  --checks "$CHECKS" \
  --report junit \
  --report-junit-path contract-report.xml \
  "$@"
