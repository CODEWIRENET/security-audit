#!/usr/bin/env bash
# Standalone installer for the CODEWIRE security suite Claude skills (macOS / Linux).
# Use this if you don't run the Claude Code plugin system.
#
# Installs every folder under ./skills/ into ~/.claude/skills/, so the suite stays
# in sync as new skills (security-audit, secrets-scanner, hook-audit, ...) are added.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_ROOT="$SCRIPT_DIR/skills"
INSTALL_ROOT="${HOME}/.claude/skills"

if [ ! -d "$SKILLS_ROOT" ]; then
  echo "Source skills folder not found: $SKILLS_ROOT" >&2
  exit 1
fi

mkdir -p "$INSTALL_ROOT"

shopt -s nullglob
for skill_dir in "$SKILLS_ROOT"/*/; do
  skill_name="$(basename "$skill_dir")"
  dest="$INSTALL_ROOT/$skill_name"
  mkdir -p "$dest"
  cp -R "$skill_dir"/. "$dest"/
  echo "Installed $skill_name -> $dest"
done

echo ""
echo "Done. Restart Claude Code for the skills to appear in the available-skills list."
