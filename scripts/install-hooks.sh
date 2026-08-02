#!/bin/sh
# Installs the repo's git hooks. Run once after cloning:
#
#   sh scripts/install-hooks.sh
#
# Only pre-push is installed; it regenerates docs/screenshots when a staging
# push changes the UI. See scripts/pre-push.sh.
set -e
cd "$(dirname "$0")/.."
hooks_dir="$(git rev-parse --git-path hooks)"
mkdir -p "$hooks_dir"
cat > "$hooks_dir/pre-push" <<'HOOK'
#!/bin/sh
exec sh "$(git rev-parse --show-toplevel)/scripts/pre-push.sh" "$@"
HOOK
chmod +x "$hooks_dir/pre-push"
echo "installed $hooks_dir/pre-push"
