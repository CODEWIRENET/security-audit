# Standalone installer for the CODEWIRE security suite Claude skills (Windows / PowerShell).
# Use this if you don't run the Claude Code plugin system.
#
# Installs every folder under ./skills/ into ~/.claude/skills/, so the suite stays
# in sync as new skills (security-audit, secrets-scanner, hook-audit, ...) are added.

$ErrorActionPreference = "Stop"

$skillsRoot   = Join-Path $PSScriptRoot "skills"
$installRoot  = Join-Path $env:USERPROFILE ".claude\skills"

if (-not (Test-Path $skillsRoot)) {
    Write-Error "Source skills folder not found: $skillsRoot"
    exit 1
}

$skills = Get-ChildItem -Path $skillsRoot -Directory
if ($skills.Count -eq 0) {
    Write-Error "No skill folders under $skillsRoot"
    exit 1
}

New-Item -ItemType Directory -Path $installRoot -Force | Out-Null

foreach ($skill in $skills) {
    $dest = Join-Path $installRoot $skill.Name
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Copy-Item -Path (Join-Path $skill.FullName "*") -Destination $dest -Recurse -Force
    Write-Host "Installed $($skill.Name) -> $dest"
}

Write-Host ""
Write-Host "Done. Restart Claude Code for the skills to appear in the available-skills list."
