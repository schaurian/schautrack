#!/bin/sh
# Keeps docs/screenshots honest on staging.
#
# Installed as a git pre-push hook (scripts/install-hooks.sh, or via lefthook).
# When a push touches staging and the UI changed, the screenshots are
# regenerated; if they came out different, the push is stopped so the new
# images go out with the change that caused them rather than a release later.
#
#   SKIP_SCREENSHOTS=1 git push     # bypass for a hurry
#   git push --no-verify            # bypass every hook
set -e

cd "$(dirname "$0")/.."

[ -n "$SKIP_SCREENSHOTS" ] && exit 0

# git feeds "<local ref> <local sha> <remote ref> <remote sha>" on stdin.
pushing_staging=0
while read -r _local_ref local_sha remote_ref _remote_sha; do
  case "$remote_ref" in
    refs/heads/staging) pushing_staging=1; head_sha="$local_sha" ;;
  esac
done
[ "$pushing_staging" = 1 ] || exit 0

# Only when something that can change a screenshot moved. Compared against the
# pushed remote branch, so a push of unrelated commits stays fast.
watch="client/src client/index.html scripts/demo-seed.ts scripts/screenshots.ts"
if git rev-parse --verify --quiet origin/staging >/dev/null; then
  if git diff --quiet origin/staging.."${head_sha:-HEAD}" -- $watch; then
    echo "pre-push: no UI changes, keeping the existing screenshots"
    exit 0
  fi
fi

if [ -n "$(git status --porcelain docs/screenshots)" ]; then
  echo "pre-push: docs/screenshots has uncommitted changes; commit or stash them first." >&2
  exit 1
fi

echo "pre-push: UI changed — regenerating screenshots (SKIP_SCREENSHOTS=1 to skip)"
sh scripts/screenshots.sh

if [ -n "$(git status --porcelain docs/screenshots)" ]; then
  echo "" >&2
  echo "pre-push: the screenshots changed:" >&2
  git status --porcelain docs/screenshots >&2
  echo "" >&2
  echo "Look them over, then include them:" >&2
  echo "    git add docs/screenshots && git commit -m 'docs: refresh screenshots' && git push" >&2
  exit 1
fi

echo "pre-push: screenshots already current"
