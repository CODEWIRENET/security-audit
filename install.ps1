# Standalone installer for the security-audit Claude skill (Windows / PowerShell).
# Use this if you don't run the Claude Code plugin system.

$ErrorActionPreference = "Stop"

$dest = Join-Path $env:USERPROFILE ".claude\skills\security-audit"
$src  = Join-Path $PSScriptRoot "skills\security-audit"

if (-not (Test-Path $src)) {
    Write-Error "Source skill folder not found: $src"
    exit 1
}

New-Item -ItemType Directory -Path $dest -Force | Out-Null
Copy-Item -Path (Join-Path $src "*") -Destination $dest -Recurse -Force

Write-Host "Installed security-audit skill to $dest"
Write-Host "Restart Claude Code for the skill to appear in the available-skills list."
