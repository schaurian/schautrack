#!/bin/sh
# Derive the next release version for `main` from the tag namespace.
#
# Prints the bare version ("1.4.2") on stdout and nothing else, so a caller can
# capture it with $(...).
#
# This exists as a script rather than inline YAML because TWO jobs need to run
# it and they must agree exactly. compute-version derives the version early, and
# create-tag re-derives it under the repo-wide tag lock to check nothing moved
# in between (#402). Two copies of this logic in two `run:` blocks would drift,
# and the drift would look exactly like the race it is there to detect.
#
# Requires a full-depth checkout: `git describe` needs the tags.
set -eu

LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
VERSION="${LATEST_TAG##v}" # strip all leading v's

MAJOR=$(echo "$VERSION" | cut -d. -f1)
MINOR=$(echo "$VERSION" | cut -d. -f2)
PATCH=$(echo "$VERSION" | cut -d. -f3)

# Commit subjects since the last tag decide the bump.
COMMITS=$(git log "${LATEST_TAG}..HEAD" --pretty=format:"%s" 2>/dev/null || git log --pretty=format:"%s")

# Each alternative carries an optional "(scope)" group so a scoped subject
# (`feat(ai): ...`, `fix(deps): ...`) matches the same branch its unscoped form
# does. Without it, `grep` never matched the scoped form at all, fell through
# to the "no prefix" patch default, and shipped two releases under the wrong
# bump (v2.5.5 should have been v2.6.0; the welcome tour's v2.4.2 should have
# been v2.5.0).
#
# The major check also accepts the Conventional Commits breaking-change marker
# `!` right before the colon (`feat!:`, `feat(api)!:`) on ANY type, per spec —
# that is the standard spelling for "breaking" and previously fell through to
# patch just like the missing scope group did.
if echo "$COMMITS" | grep -qiE "^(breaking|major)(\([^)]*\))?:|^[a-z]+(\([^)]*\))?!:"; then
  MAJOR=$((MAJOR + 1))
  MINOR=0
  PATCH=0
elif echo "$COMMITS" | grep -qiE "^(feat|feature|minor)(\([^)]*\))?:"; then
  MINOR=$((MINOR + 1))
  PATCH=0
elif echo "$COMMITS" | grep -qiE "^(fix|patch|chore|docs|refactor)(\([^)]*\))?:"; then
  PATCH=$((PATCH + 1))
else
  # No conventional prefix: a patch bump is the safe default.
  PATCH=$((PATCH + 1))
fi

printf '%s.%s.%s\n' "$MAJOR" "$MINOR" "$PATCH"
