#!/usr/bin/env bash
# Standalone installer for the security-audit Claude skill (macOS / Linux).
# Use this if you don't run the Claude Code plugin system.

set -euo pipefail

DEST="${HOME}/.claude/skills/security-audit"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/skills/security-audit"

if [ ! -d "$SRC" ]; then
  echo "Source skill folder not found: $SRC" >&2
  exit 1
fi

mkdir -p "$DEST"
cp -R "$SRC"/. "$DEST"/

echo "Installed security-audit skill to $DEST"
echo "Restart Claude Code for the skill to appear in the available-skills list."
