#!/usr/bin/env bash
set -euo pipefail

# Determine next semver based on Conventional Commits since last tag.

last_tag=$(git describe --tags --match "v[0-9]*.[0-9]*.[0-9]*" --abbrev=0 2>/dev/null || true)
if [[ -z "$last_tag" ]]; then
  last_tag="v0.0.0"
  range=""
else
  range="${last_tag}..HEAD"
fi

major=0
minor=0
patch=0

if [[ -n "$range" ]]; then
  mapfile -t commits < <(git log --format="%s%n%b" "$range")
else
  mapfile -t commits < <(git log --format="%s%n%b")
fi

for line in "${commits[@]}"; do
  # Normalize to lowercase for detection
  lower=$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')
  if [[ "$lower" == *"breaking change"* ]] || [[ "$lower" =~ ^[a-z]+!\: ]]; then
    major=1
    break
  elif [[ "$lower" =~ ^feat(\(.+\))?\: ]]; then
    minor=1
  elif [[ "$lower" =~ ^fix(\(.+\))?\: ]]; then
    if [[ $minor -eq 0 ]]; then
      patch=1
    fi
  fi
done

# Default to patch if no commits matched anything (but commits exist).
if [[ ${#commits[@]} -gt 0 && $major -eq 0 && $minor -eq 0 && $patch -eq 0 ]]; then
  patch=1
fi

IFS='.' read -r cur_major cur_minor cur_patch <<<"${last_tag#v}"

if [[ $major -eq 1 ]]; then
  cur_major=$((cur_major + 1))
  cur_minor=0
  cur_patch=0
elif [[ $minor -eq 1 ]]; then
  cur_minor=$((cur_minor + 1))
  cur_patch=0
else
  cur_patch=$((cur_patch + 1))
fi

next_version="v${cur_major}.${cur_minor}.${cur_patch}"
printf '%s\n' "$next_version"
