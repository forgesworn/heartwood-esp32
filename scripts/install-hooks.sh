#!/usr/bin/env bash
# Install git hooks for this repo. Run once per clone.
#
# The hook scripts live in scripts/git-hooks/ (tracked). This installer
# symlinks them into .git/hooks/ (not tracked) so `git commit` picks them up.

set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
HOOKS_DIR="$REPO_ROOT/.git/hooks"
SOURCE_DIR="$REPO_ROOT/scripts/git-hooks"

if [ ! -d "$SOURCE_DIR" ]; then
  echo "ERROR: $SOURCE_DIR does not exist" >&2
  exit 1
fi

for hook in "$SOURCE_DIR"/*; do
  [ -f "$hook" ] || continue
  name=$(basename "$hook")
  target="$HOOKS_DIR/$name"
  chmod +x "$hook"
  ln -sf "$hook" "$target"
  echo "installed: $name -> scripts/git-hooks/$name"
done

echo
echo "Hooks installed. Verify with: python3 scripts/git-hooks/pre-commit --dry-run"
