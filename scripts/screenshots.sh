#!/bin/sh
# Regenerate docs/screenshots from a throwaway stack.
#
#   npm run screenshots
#
# Brings up compose.test.yml (it already has CAPTCHA_BYPASS and a disposable
# database), seeds the demo account, and captures the set. The stack is left
# running so repeat runs are quick — `npm run test:e2e:down` clears it.
set -e

cd "$(dirname "$0")/.."

COMPOSE="docker compose -f compose.test.yml"

echo "==> building and starting the test stack"
if ! $COMPOSE up -d --build --wait; then
  # Some Docker setups can't reach the registry to re-resolve base images that
  # are already present locally; the classic builder uses them as-is.
  echo "==> buildkit build failed, retrying with the classic builder"
  DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 $COMPOSE up -d --build --wait
fi

echo "==> seeding demo data"
npx tsx scripts/demo-seed.ts

echo "==> capturing screenshots"
npx tsx scripts/screenshots.ts

echo "==> done. Stack still running; 'npm run test:e2e:down' to stop it."
