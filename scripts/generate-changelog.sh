#!/usr/bin/env bash
set -euo pipefail

version_tag="${1:-}"
last_tag=$(git describe --tags --match "v[0-9]*.[0-9]*.[0-9]*" --abbrev=0 2>/dev/null || true)

if [[ -n "$last_tag" ]]; then
  range="${last_tag}..HEAD"
else
  range=""
fi

{
  if [[ -n "$version_tag" ]]; then
    printf "## %s\n\n" "$version_tag"
  fi

  printf "### Changes\n"
  printf "\n"

  if [[ -n "$range" ]]; then
    git log --format='- %s (%h)' "$range"
  else
    git log --format='- %s (%h)'
  fi
} | sed '/^$/N;/^\n$/D'
