#!/bin/sh
# Run the Playwright end-to-end suite against a throwaway compose.test.yml stack.
#
#   npm run test:e2e                 -> sh scripts/e2e.sh
#   npm run test:e2e:ui              -> sh scripts/e2e.sh --ui
#   npm run test:e2e -- --grep auth  -> extra args are forwarded to playwright
#
# Why this is a script and not a one-liner in package.json:
#
# The run has to tear the stack down *unconditionally* but exit with the
# *suite's* status. The old inline chain ended in `; docker compose ... down`,
# so the shell reported the teardown's status and a red suite exited 0 (#320).
# Fixing that inline needs a `status=$?; ...; exit $status` dance that (a) would
# have to be duplicated verbatim in `test:e2e` and `test:e2e:ui` and drift, and
# (b) still leaves a stack running when a developer hits Ctrl-C, which is the
# normal way to end a `--ui` session. A trap handles the signal case, and one
# file keeps the two npm scripts in step.
#
# `test:e2e:setup` and `test:e2e:down` stay inline in package.json on purpose:
# `setup` is `down -v; up --wait && seed`, whose status is already that of the
# `&&` chain, so a failing `up` and a failing seed both propagate; `down` is a
# single command. In both cases the leading/only `down -v` status is discarded,
# which is deliberate — there is nothing to remove on a fresh machine, and a
# genuine problem (no daemon, bad compose file) resurfaces immediately from the
# `up` that follows.
#
# Everything below is POSIX sh, no bashisms: npm runs scripts with `/bin/sh`,
# which is dash on Debian/Ubuntu, including `ubuntu-latest` runners.

cd "$(dirname "$0")/.." || exit 1

COMPOSE="docker compose -f compose.test.yml"

teardown() {
  # Unconditional: a leaked stack keeps port 3001 and its volumes, which breaks
  # the next run. Its own status is discarded on purpose so that it can never
  # overwrite the suite's.
  echo "==> tearing down the test stack"
  $COMPOSE down || true
}

# Ctrl-C and SIGTERM must still tear down. 128 + signal number, as usual.
trap 'teardown; exit 130' INT
trap 'teardown; exit 143' TERM

# Clear anything left over from a previous run (see the note above on why the
# status is ignored here).
echo "==> clearing any previous test stack"
$COMPOSE down -v

status=0
{
  echo "==> building and starting the test stack" &&
    $COMPOSE up -d --build --wait &&
    echo "==> seeding the test user" &&
    npx tsx e2e/setup-test-user.ts &&
    echo "==> running playwright" &&
    npx playwright test "$@"
} || status=$?

teardown

exit "$status"
